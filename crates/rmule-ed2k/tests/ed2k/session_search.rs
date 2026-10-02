//! Searching through the session: rejected before login, written as a search
//! request after it, and results folded into an event — a malformed result
//! skipped without closing the session. A related-files search is written as
//! the one `related::<HASH>` term, and only toward a server that granted it.

use rmule_ed2k::{
    CommandRejectReason, Ed2kCommand, Ed2kCommandKind, Ed2kEvent, Output, SearchRequest,
    SearchResultSkipReason, SearchResults, ServerCapability, ServerTcpFlags,
};
use rmule_primitives::{
    Ed2kText, FileHash, KeywordQuery, Packet, PacketProtocol, RelatedFilesQuery, Tag, TagName,
    TagValue,
};

fn query() -> KeywordQuery {
    KeywordQuery::new(Ed2kText::from_utf8("ubuntu")).unwrap()
}

fn search_result_packet() -> Packet {
    let mut payload = Vec::new();
    payload.extend_from_slice(&1_u32.to_le_bytes());
    payload.extend_from_slice(crate::fixture::hash(0xaa).as_bytes());
    payload.extend_from_slice(&0x0100_0085_u32.to_le_bytes());
    payload.extend_from_slice(&4668_u16.to_le_bytes());
    payload.extend_from_slice(&2_u32.to_le_bytes());
    payload.extend_from_slice(
        &Tag::new(
            TagName::compact_id(0x01),
            TagValue::String(Ed2kText::from_utf8("packed.bin")),
        )
        .encode(),
    );
    payload.extend_from_slice(&Tag::new(TagName::compact_id(0x02), TagValue::U32(8192)).encode());
    Packet::new(PacketProtocol::Edonkey, 0x33, payload)
}

#[test]
fn search_before_login_emits_command_rejection() {
    let mut session = crate::fixture::started_session(0x42);

    session.handle_command(Ed2kCommand::Search {
        query: query().into(),
    });

    assert!(matches!(
        session.poll_output(),
        Some(Output::Event(Ed2kEvent::CommandRejected {
            command: Ed2kCommandKind::Search,
            reason: CommandRejectReason::NotLoggedIn,
        }))
    ));
}

#[test]
fn search_after_login_writes_search_request() {
    let mut session = crate::fixture::started_session(0x42);
    crate::fixture::login_with_flags(&mut session, None);
    let expected = query();

    session.handle_command(Ed2kCommand::Search {
        query: expected.clone().into(),
    });

    let Some(Output::Write(bytes)) = session.poll_output() else {
        panic!("expected search request write");
    };
    let packet = Packet::decode_exact(&bytes).unwrap();
    assert_eq!(
        SearchRequest::decode_packet(&packet).unwrap().query(),
        &expected
    );
}

#[test]
fn well_formed_search_result_emits_search_results_found() {
    let mut session = crate::fixture::started_session(0x42);

    session.handle_bytes(&search_result_packet().encode());

    match session.poll_output() {
        Some(Output::Event(Ed2kEvent::SearchResultsFound { results, .. })) => {
            assert_eq!(results[0].primary_name().to_display_string(), "packed.bin");
            assert_eq!(results[0].file_size(), 8192);
        }
        other => panic!("expected SearchResultsFound, got {other:?}"),
    }
}

/// Derived, not captured (no bench answer has said more): the trailing
/// byte as ed2k-server writes it on a capped page (`search.rs:186-187`) and as
/// eMule reads it (`SearchList.cpp:266-277`) — `0x01` more, anything else none.
#[test]
fn the_more_results_byte_reaches_the_event() {
    for (tail, more) in [(0x01, true), (0x00, false), (0x02, false)] {
        let mut session = crate::fixture::started_session(0x42);
        let packet = search_result_packet();
        let mut payload = packet.payload().to_vec();
        payload.push(tail);
        session.handle_bytes(&Packet::new(PacketProtocol::Edonkey, 0x33, payload).encode());
        match session.poll_output() {
            Some(Output::Event(Ed2kEvent::SearchResultsFound {
                results,
                more_available,
                ..
            })) => {
                assert_eq!(results.len(), 1);
                assert_eq!(more_available, more, "tail {tail:#04x}");
            }
            other => panic!("expected SearchResultsFound, got {other:?}"),
        }
    }
}

/// Derived from eMule's `SearchMore` (`SearchResultsWnd.cpp:1273-1289`: a bare
/// `Packet()`, eDonkey protocol, no body) and ed2k-server's reader (it reads
/// the opcode alone, `connection.rs:519`): the request is the opcode and
/// nothing else, and never leaves before login.
#[test]
fn a_request_for_more_is_the_bare_opcode_after_login_only() {
    let mut session = crate::fixture::started_session(0x42);
    session.handle_command(Ed2kCommand::QueryMoreResults);
    assert!(matches!(
        session.poll_output(),
        Some(Output::Event(Ed2kEvent::CommandRejected {
            command: Ed2kCommandKind::QueryMoreResults,
            reason: CommandRejectReason::NotLoggedIn,
        }))
    ));

    crate::fixture::login_with_flags(&mut session, None);
    session.handle_command(Ed2kCommand::QueryMoreResults);
    let Some(Output::Write(bytes)) = session.poll_output() else {
        panic!("expected the request's write");
    };
    assert_eq!(&bytes[..], [0xE3, 0x01, 0x00, 0x00, 0x00, 0x21]);
}

#[test]
fn malformed_search_result_is_skipped_without_closing_and_next_command_writes() {
    let mut session = crate::fixture::started_session(0x42);
    crate::fixture::login_with_flags(&mut session, None);
    let malformed = Packet::new(PacketProtocol::Edonkey, 0x33, vec![1, 0, 0, 0]).encode();

    session.handle_bytes(&malformed);

    // The one row the batch announced is not there: the answer stands with
    // that row skipped.
    match session.poll_output() {
        Some(Output::Event(Ed2kEvent::SearchResultsFound {
            results, skipped, ..
        })) => {
            assert!(results.is_empty());
            assert_eq!(skipped, [SearchResultSkipReason::MalformedPayload]);
        }
        other => panic!("expected the answer with its row skipped, got {other:?}"),
    }

    session.handle_command(Ed2kCommand::Search {
        query: query().into(),
    });
    assert!(matches!(session.poll_output(), Some(Output::Write(_))));
}

#[test]
fn compressed_search_result_inflates_and_emits_search_results_found() {
    let mut session = crate::fixture::started_session(0x42);

    let compressed = [
        0xd4, 0x2c, 0x00, 0x00, 0x00, 0x33, 0x78, 0x9c, 0x63, 0x64, 0x60, 0x60, 0x70, 0x41, 0x03,
        0xad, 0x0c, 0x0c, 0x8c, 0x36, 0x42, 0x4c, 0x40, 0x99, 0x26, 0x46, 0x2e, 0x86, 0x82, 0xc4,
        0xe4, 0xec, 0xd4, 0x14, 0xbd, 0xa4, 0xcc, 0xbc, 0x66, 0x26, 0x06, 0x05, 0x06, 0x06, 0x00,
        0xf6, 0x42, 0x0a, 0x19,
    ];

    session.handle_bytes(&compressed);

    match session.poll_output() {
        Some(Output::Event(Ed2kEvent::SearchResultsFound { results, .. })) => {
            assert_eq!(results[0].file_hash(), crate::fixture::hash(0x44));
            assert_eq!(results[0].primary_name().to_display_string(), "packed.bin");
        }
        other => panic!("expected SearchResultsFound from compressed frame, got {other:?}"),
    }
}

#[test]
fn search_results_packet_constructor_round_trips_through_session_event() {
    let mut session = crate::fixture::started_session(0x42);
    let decoded = SearchResults::decode_packet(&search_result_packet()).unwrap();

    session.handle_bytes(&decoded.encode_packet().encode());

    assert!(matches!(
        session.poll_output(),
        Some(Output::Event(Ed2kEvent::SearchResultsFound { results, .. }))
            if results[0].primary_name().to_display_string() == "packed.bin"
    ));
}

fn related_query() -> RelatedFilesQuery {
    RelatedFilesQuery::new(
        FileHash::from_bytes([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ]),
        Ed2kText::from_utf8("holiday video.avi"),
    )
}

/// **Derived, not captured**: the frame eMule and aMule write for a related
/// search, laid out from their source — eMule `SearchResultsWnd.cpp:1678-1685`
/// and aMule `SearchListCtrl.cpp:1003-1012` build `related::` plus the hash in
/// upper-case hex (eMule `OtherFunctions.cpp:60,1191-1193`, aMule
/// `MD4Hash.h:182-196`), lexed as one token and written as node `0x01`
/// (eMule `Scanner.l:76,317`, `SearchResultsWnd.cpp:869-873`; aMule
/// `Scanner.l:45,59-62`). No capture of either client exists
/// (the bench run archive, 48 archives, holds no `related:`).
const DERIVED_RELATED_SEARCH_FRAME: &[u8] =
    b"\xe3\x2d\x00\x00\x00\x16\x01\x29\x00related::0123456789ABCDEFFEDCBA9876543210";

#[test]
fn a_related_search_writes_the_one_term_emule_and_amule_write() {
    let mut session = crate::fixture::started_session(0x42);
    crate::fixture::login_with_flags(
        &mut session,
        Some(ServerTcpFlags::from_bits(ServerTcpFlags::RELATEDSEARCH)),
    );

    session.handle_command(Ed2kCommand::Search {
        query: related_query().into(),
    });

    let Some(Output::Write(bytes)) = session.poll_output() else {
        panic!("expected the related search request write");
    };
    assert_eq!(&*bytes, DERIVED_RELATED_SEARCH_FRAME);
}

#[test]
fn a_related_search_toward_a_server_without_the_grant_is_refused_unsent() {
    let mut session = crate::fixture::started_session(0x42);
    // Everything Lugdunum grants except `0x40`.
    crate::fixture::login_with_flags(
        &mut session,
        Some(ServerTcpFlags::from_bits(
            0x17F9 & !ServerTcpFlags::RELATEDSEARCH,
        )),
    );

    session.handle_command(Ed2kCommand::Search {
        query: related_query().into(),
    });

    assert!(matches!(
        session.poll_output(),
        Some(Output::Event(Ed2kEvent::CommandRejected {
            command: Ed2kCommandKind::Search,
            reason: CommandRejectReason::UnsupportedServerCapability {
                capability: ServerCapability::RelatedSearch,
            },
        }))
    ));
    assert!(session.poll_output().is_none(), "nothing reaches the wire");
    session.handle_command(Ed2kCommand::Search {
        query: query().into(),
    });
    assert!(
        matches!(session.poll_output(), Some(Output::Write(_))),
        "the session stays usable for a keyword search"
    );
}
