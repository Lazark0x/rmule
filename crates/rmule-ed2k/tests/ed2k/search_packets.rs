//! The search request on the wire: one term per word, aMule's `AND`-marker
//! interleave, how each filter becomes a term, and where a 64-bit bound widens
//! the node instead of clamping it. The expected payloads here are hand-laid
//! wire goldens **derived** from the writers `docs/protocol/search-request.md`
//! cites — no archive holds a captured `OP_SEARCHREQUEST`.

use rmule_ed2k::{
    ClientPacket, SearchRequest, SearchResultSkipReason, SearchResults, ServerPacket,
};
use rmule_primitives::{
    ClientId, Ed2kFileClass, Ed2kText, FileHash, KeywordQuery, Packet, PacketProtocol, PeerSource,
    Tag, TagName, TagValue,
};

const FT_FILENAME: u8 = 0x01;
const FT_FILESIZE: u8 = 0x02;
const FT_FILETYPE: u8 = 0x03;
const FT_FILEFORMAT: u8 = 0x04;
const FT_SOURCES: u8 = 0x15;
const FT_COMPLETE_SOURCES: u8 = 0x30;
const FT_FILESIZE_HI: u8 = 0x3A;

fn search_query(phrase: &str) -> KeywordQuery {
    KeywordQuery::new(Ed2kText::from_utf8(phrase)).unwrap()
}

fn tag(id: u8, value: TagValue) -> Tag {
    Tag::new(TagName::compact_id(id), value)
}

fn search_row(hash: FileHash, client_id: ClientId, tcp_port: u16, tags: Vec<Tag>) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(hash.as_bytes());
    payload.extend_from_slice(&client_id.as_u32().to_le_bytes());
    payload.extend_from_slice(&tcp_port.to_le_bytes());
    payload.extend_from_slice(&(tags.len() as u32).to_le_bytes());
    for tag in tags {
        payload.extend_from_slice(&tag.encode());
    }
    payload
}

fn search_result_packet(rows: Vec<Vec<u8>>) -> Packet {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(rows.len() as u32).to_le_bytes());
    for row in rows {
        payload.extend_from_slice(&row);
    }
    Packet::new(PacketProtocol::Edonkey, 0x33, payload)
}

#[test]
fn search_request_encodes_packet_and_decodes_through_umbrella() {
    let query = search_query("ubuntu iso");
    let request = SearchRequest::from_query(query.clone());
    let packet = request.encode_packet();

    assert_eq!(packet.protocol(), PacketProtocol::Edonkey);
    assert_eq!(packet.opcode(), 0x16);
    // Derived (`docs/protocol/search-request.md`): one `0x01` term per word,
    // the AND marker before every term but the last.
    assert_eq!(
        packet.payload(),
        &[
            0x00, 0x00, // AND
            0x01, 0x06, 0x00, b'u', b'b', b'u', b'n', b't', b'u', //
            0x01, 0x03, 0x00, b'i', b's', b'o',
        ]
    );

    match ClientPacket::decode(&packet).unwrap() {
        ClientPacket::SearchRequest(decoded) => assert_eq!(decoded.query(), &query),
        other => panic!("expected SearchRequest, got {other:?}"),
    }
}

#[test]
fn search_request_program_filter_uses_historical_pro_wire_label() {
    let query = search_query("editor").with_file_type(Ed2kFileClass::Program);
    let packet = SearchRequest::from_query(query).encode_packet();

    assert_eq!(
        packet.payload(),
        &[
            0x00,
            0x00, // AND
            0x01,
            0x06,
            0x00,
            b'e',
            b'd',
            b'i',
            b't',
            b'o',
            b'r', // phrase
            0x02,
            0x03,
            0x00,
            b'P',
            b'r',
            b'o', // FT_FILETYPE value
            0x01,
            0x00,
            FT_FILETYPE,
        ]
    );

    let decoded = SearchRequest::decode_packet(&packet).unwrap();
    assert_eq!(decoded.query().file_type(), Some(Ed2kFileClass::Program));
}

/// aMule folds Archive and CD-image into `"Pro"` before the term is written
/// ("eDonkeyHybrid 0.48 uses type \"Pro\" for archives files",
/// `SearchList.cpp:676-684`) — the network has no `"Arc"`/`"Iso"` search term.
/// The three classes therefore share one wire form, and a decode of that form
/// can only report the one it names.
#[test]
fn archive_and_cd_image_type_filters_ride_the_pro_wire_term() {
    for class in [
        Ed2kFileClass::Program,
        Ed2kFileClass::Archive,
        Ed2kFileClass::CdImage,
    ] {
        let packet =
            SearchRequest::from_query(search_query("editor").with_file_type(class)).encode_packet();
        assert!(
            packet.payload().windows(3).any(|w| w == b"Pro"),
            "{class:?} must reach the wire as \"Pro\""
        );
        assert_eq!(
            SearchRequest::decode_packet(&packet)
                .unwrap()
                .query()
                .file_type(),
            Some(Ed2kFileClass::Program),
        );
    }
}

/// The class aMule's dropdown offers that rmule's old four-way type did not
/// (`ED2KFTSTR_DOCUMENT = "Doc"`, `FileTags.h:125`).
#[test]
fn document_type_filter_uses_the_doc_wire_term() {
    let packet =
        SearchRequest::from_query(search_query("thesis").with_file_type(Ed2kFileClass::Document))
            .encode_packet();
    assert!(packet.payload().windows(3).any(|w| w == b"Doc"));
    assert_eq!(
        SearchRequest::decode_packet(&packet)
            .unwrap()
            .query()
            .file_type(),
        Some(Ed2kFileClass::Document),
    );
}

/// The whole constraint set at once, byte-for-byte, in aMule's order — phrase,
/// `FT_FILETYPE`, min `FT_FILESIZE`, max `FT_FILESIZE`, `FT_SOURCES`,
/// `FT_FILEFORMAT` (`SearchList.cpp:739-780`) — with the AND marker *prepended*
/// to every term but the last, the "lugdunummaster" interleave
/// (`SearchList.cpp:728-737`).
#[test]
fn every_constraint_encodes_in_amules_order_with_the_prepended_ands() {
    let query = search_query("bunny")
        .with_file_type(Ed2kFileClass::Video)
        .with_min_size(1024)
        .with_max_size(4096)
        .with_min_availability(5)
        .with_extension(Ed2kText::from_utf8("avi"));
    let packet = SearchRequest::from_query(query.clone()).encode_packet();

    // Six terms; the AND marker precedes each one *but the last*, interleaved
    // — `AND phrase AND type AND min AND max AND sources ext`, never the
    // front-loaded `AND AND AND AND AND phrase type …` of a prefix tree.
    const AND: [u8; 2] = [0x00, 0x00];
    let phrase: Vec<u8> = [&[0x01, 0x05, 0x00][..], b"bunny"].concat();
    let file_type: Vec<u8> = [
        &[0x02, 0x05, 0x00][..],
        b"Video",
        &[0x01, 0x00, FT_FILETYPE],
    ]
    .concat();
    let min_size = [0x03, 0x00, 0x04, 0x00, 0x00, 0x01, 0x01, 0x00, FT_FILESIZE];
    let max_size = [0x03, 0x00, 0x10, 0x00, 0x00, 0x02, 0x01, 0x00, FT_FILESIZE];
    let sources = [0x03, 0x05, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, FT_SOURCES];
    let extension: Vec<u8> = [
        &[0x02, 0x03, 0x00][..],
        b"avi",
        &[0x01, 0x00, FT_FILEFORMAT],
    ]
    .concat();

    let mut expected: Vec<u8> = Vec::new();
    for term in [
        phrase.as_slice(),
        file_type.as_slice(),
        &min_size,
        &max_size,
        &sources,
    ] {
        expected.extend_from_slice(&AND);
        expected.extend_from_slice(term);
    }
    expected.extend_from_slice(&extension);

    assert_eq!(packet.payload(), expected.as_slice());
    assert_eq!(
        SearchRequest::decode_packet(&packet).unwrap().query(),
        &query
    );
}

/// A phrase of several words is one `0x01` term per word, interleaved with the
/// constraints exactly as aMule interleaves its one joined term: ed2k-server
/// looks each term up whole in its word index, so `"ubuntu desktop"` as one
/// term finds nothing there.
#[test]
fn a_multi_word_phrase_goes_out_as_one_term_per_word_anded() {
    let query = search_query("  ubuntu AND desktop ").with_min_availability(3);
    let packet = SearchRequest::from_query(query).encode_packet();
    let expected: Vec<u8> = [
        &[0x00, 0x00][..],
        &[0x01, 0x06, 0x00],
        b"ubuntu",
        &[0x00, 0x00],
        &[0x01, 0x07, 0x00],
        b"desktop",
        &[0x03, 0x03, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, FT_SOURCES],
    ]
    .concat();
    assert_eq!(packet.payload(), expected.as_slice());
    assert_eq!(
        SearchRequest::decode_packet(&packet)
            .unwrap()
            .query()
            .phrase()
            .to_display_string(),
        "ubuntu desktop"
    );
}

/// A quoted run is one term and keeps its quotes, as eMule sends it.
#[test]
fn a_quoted_run_stays_one_term_with_its_quotes() {
    let packet = SearchRequest::from_query(search_query(r#"live "at wembley""#)).encode_packet();
    let expected: Vec<u8> = [
        &[0x00, 0x00, 0x01, 0x04, 0x00][..],
        b"live",
        &[0x01, 0x0c, 0x00],
        br#""at wembley""#,
    ]
    .concat();
    assert_eq!(packet.payload(), expected.as_slice());
}

/// aMule and eMule write a bound only when it is non-zero; zero is no term.
#[test]
fn a_zero_bound_writes_no_term() {
    let bare = SearchRequest::from_query(search_query("bunny")).encode_packet();
    let zeroed = SearchRequest::from_query(
        search_query("bunny")
            .with_min_size(0)
            .with_max_size(0)
            .with_min_availability(0),
    )
    .encode_packet();
    assert_eq!(zeroed.payload(), bare.payload());
}

/// `FT_FILEFORMAT` goes out bare, whatever dot the operator typed (eMule
/// `SearchParamsWnd.cpp:945`).
#[test]
fn an_extension_goes_out_without_its_dot() {
    let dotted = SearchRequest::from_query(
        search_query("bunny").with_extension(Ed2kText::from_utf8(".avi")),
    )
    .encode_packet();
    let expected: Vec<u8> = [
        &[0x00, 0x00, 0x01, 0x05, 0x00][..],
        b"bunny",
        &[0x02, 0x03, 0x00],
        b"avi",
        &[0x01, 0x00, FT_FILEFORMAT],
    ]
    .concat();
    assert_eq!(dotted.payload(), expected.as_slice());
}

/// Raw UTF-8, no BOM and no server gate (aMule `SearchList.cpp:1606-1610`).
#[test]
fn an_accented_word_goes_out_as_its_utf8_bytes() {
    let packet = SearchRequest::from_query(search_query("café")).encode_packet();
    assert_eq!(
        packet.payload(),
        &[0x01, 0x05, 0x00, b'c', b'a', b'f', 0xc3, 0xa9]
    );
}

/// The one term aMule's marker interleave leaves unmarked is the last one, so a
/// phrase with a single constraint is `AND phrase constraint` — two terms, one
/// marker — not a prefix tree.
#[test]
fn a_single_constraint_prepends_exactly_one_and() {
    let packet =
        SearchRequest::from_query(search_query("bunny").with_min_availability(20)).encode_packet();
    assert_eq!(
        packet.payload(),
        &[
            0x00, 0x00, // AND
            0x01, 0x05, 0x00, b'b', b'u', b'n', b'n', b'y', // phrase
            0x03, 0x14, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, FT_SOURCES,
        ]
    );
}

/// `CSearchExprTarget::WriteMetaDataSearchParam` (`SearchList.cpp:215-232`):
/// a bound past `0xFFFFFFFF` widens to the `0x08` node **only** when the
/// addressee advertised large-file support; otherwise the value is pinned to
/// `0xFFFFFFFF` in an ordinary `0x03` node. Both packets stay legal — the
/// clamped one just asks a wider question.
#[test]
fn an_oversize_size_bound_widens_only_for_a_large_file_server() {
    let over = u64::from(u32::MAX) + 1;
    let query = search_query("bunny").with_min_size(over);

    let clamped = SearchRequest::from_query(query.clone());
    assert!(!clamped.uses_64bit());
    #[rustfmt::skip]
    let clamped_wire = [
        0x00, 0x00,                                                  // AND
        0x01, 0x05, 0x00, b'b', b'u', b'n', b'n', b'y',              // phrase
        0x03, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x01, 0x00, FT_FILESIZE, // min size, pinned
    ];
    assert_eq!(clamped.encode_packet().payload(), &clamped_wire);

    let wide = SearchRequest::from_query(query).with_large_file_support(true);
    assert!(wide.uses_64bit());
    let packet = wide.encode_packet();
    #[rustfmt::skip]
    let wide_wire = [
        0x00, 0x00,                                                  // AND
        0x01, 0x05, 0x00, b'b', b'u', b'n', b'n', b'y',              // phrase
        0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,        // min size, 64-bit
        0x01, 0x01, 0x00, FT_FILESIZE,
    ];
    assert_eq!(packet.payload(), &wide_wire);
    // The `0x08` node is self-describing: decoding one re-establishes the
    // large-file fact, so the request re-encodes to the bytes it arrived as.
    let decoded = SearchRequest::decode_packet(&packet).unwrap();
    assert_eq!(decoded.query().min_size(), Some(over));
    assert_eq!(decoded.encode_packet().payload(), packet.payload());
}

/// A bound that fits in 32 bits is a `0x03` node whatever the server supports —
/// large-file capability widens nothing on its own.
#[test]
fn a_small_bound_never_widens_and_never_marks_the_packet_64bit() {
    let request = SearchRequest::from_query(search_query("bunny").with_max_size(4096))
        .with_large_file_support(true);
    assert!(!request.uses_64bit());
    assert!(!request.encode_packet().payload().contains(&0x08));
}

/// The regression guard for constraints: a query with no constraints must
/// encode to exactly the bytes it did before constraints existed — one bare
/// `0x01` phrase node, no boolean wrapper.
#[test]
fn a_bare_phrase_is_byte_identical_with_and_without_large_file_support() {
    let bare = SearchRequest::from_query(search_query("ubuntu"))
        .encode_packet()
        .payload()
        .to_vec();
    assert_eq!(bare, [&[0x01, 0x06, 0x00][..], b"ubuntu"].concat());
    assert_eq!(
        SearchRequest::from_query(search_query("ubuntu"))
            .with_large_file_support(true)
            .encode_packet()
            .payload(),
        bare.as_slice(),
    );
}

#[test]
fn search_results_decodes_count_prefixed_row() {
    let packet = search_result_packet(vec![search_row(
        crate::fixture::hash(0xaa),
        ClientId::from_u32(0x0100_007f),
        4662,
        vec![
            tag(
                FT_FILENAME,
                TagValue::String(Ed2kText::from_utf8("ubuntu.iso")),
            ),
            tag(FT_FILESIZE, TagValue::U32(1024)),
            tag(FT_SOURCES, TagValue::U32(7)),
        ],
    )]);

    let decoded = SearchResults::decode_packet(&packet).unwrap();
    let result = &decoded.results()[0];

    assert_eq!(result.file_hash(), crate::fixture::hash(0xaa));
    assert_eq!(result.file_size(), 1024);
    assert_eq!(result.primary_name().to_display_string(), "ubuntu.iso");
    assert_eq!(
        result.sources(),
        &[PeerSource::new(ClientId::from_u32(0x0100_007f), 4662)]
    );
    assert_eq!(result.reported_availability(), Some(7));
}

#[test]
fn a_search_row_with_the_sentinel_id_keeps_its_file_and_names_no_source() {
    let packet = search_result_packet(vec![search_row(
        crate::fixture::hash(0xab),
        ClientId::from_u32(PeerSource::IPV6_SENTINEL),
        4662,
        vec![
            tag(
                FT_FILENAME,
                TagValue::String(Ed2kText::from_utf8("ubuntu.iso")),
            ),
            tag(FT_FILESIZE, TagValue::U32(1024)),
        ],
    )]);

    let decoded = SearchResults::decode_packet(&packet).unwrap();
    let result = &decoded.results()[0];
    assert_eq!(result.file_hash(), crate::fixture::hash(0xab));
    assert!(
        result.sources().is_empty(),
        "0xFFFFFFFF is not 255.255.255.255: {:?}",
        result.sources()
    );
}

#[test]
fn search_results_decode_lugdunum_uint8_source_tags() {
    let packet = search_result_packet(vec![search_row(
        FileHash::from_hex("8E302DB5B806A25C9385FC23F21062D2").unwrap(),
        ClientId::from_u32(0x0300_12ac),
        4662,
        vec![
            tag(
                FT_FILENAME,
                TagValue::String(Ed2kText::from_utf8("shared.bin")),
            ),
            tag(FT_FILESIZE, TagValue::U32(65_536)),
            tag(FT_SOURCES, TagValue::U8(1)),
            tag(FT_COMPLETE_SOURCES, TagValue::U8(1)),
        ],
    )]);

    let decoded = SearchResults::decode_packet(&packet).unwrap();
    let result = &decoded.results()[0];

    assert_eq!(
        result.file_hash().to_hex_upper(),
        "8E302DB5B806A25C9385FC23F21062D2"
    );
    assert_eq!(result.file_size(), 65_536);
    assert_eq!(result.primary_name().to_display_string(), "shared.bin");
    assert_eq!(result.reported_availability(), Some(1));
    assert_eq!(result.complete_sources(), Some(1));
    assert!(
        result.extra_tags().is_empty(),
        "both source counts are typed fields now, not leftovers"
    );
}

/// Both counts are integer tags of *whatever width the writer chose*: every
/// *Mule narrows an integer tag to its smallest type, so a file with 300
/// sources arrives as `TAGTYPE_UINT16` where one with 3 arrives as `_UINT8`.
/// Bytes are hand-built rather than round-tripped because that width is the
/// point. Before the fix the `0x08` tag failed the row — and one failed row skips
/// the whole packet, so a single popular file blanked every result in it.
#[test]
fn search_results_decode_uint16_source_counts() {
    let mut payload = vec![0x01, 0x00, 0x00, 0x00];
    payload.extend_from_slice(&[0xAB; FileHash::BYTE_LEN]);
    payload.extend_from_slice(&[0xAC, 0x12, 0x00, 0x03]); // client id
    payload.extend_from_slice(&[0x36, 0x12]); // tcp port
    payload.extend_from_slice(&[0x04, 0x00, 0x00, 0x00]); // tag count
    payload.extend_from_slice(&[0x99, FT_FILENAME]); // STR9
    payload.extend_from_slice(b"alpha.bin");
    payload.extend_from_slice(&[0x83, FT_FILESIZE, 0x00, 0xE8, 0x03, 0x00]); // u32 256000
    payload.extend_from_slice(&[0x88, FT_SOURCES, 0x2C, 0x01]); // u16 300
    payload.extend_from_slice(&[0x88, FT_COMPLETE_SOURCES, 0x90, 0x01]); // u16 400

    let packet = Packet::new(PacketProtocol::Edonkey, 0x33, payload);
    let decoded = SearchResults::decode_packet(&packet).unwrap();
    let result = &decoded.results()[0];

    assert_eq!(result.primary_name().to_display_string(), "alpha.bin");
    assert_eq!(result.reported_availability(), Some(300));
    assert_eq!(result.complete_sources(), Some(400));
}

/// A count that is not an integer at all is still a malformed row.
/// A known tag of the wrong type costs its row, not the batch: the row's
/// bytes were read whole, so the rows after it are read.
#[test]
fn search_results_skip_alone_a_row_with_a_non_integer_source_count() {
    let bad = search_row(
        crate::fixture::hash(0xab),
        ClientId::from_u32(0x0100_007f),
        4662,
        vec![
            tag(
                FT_FILENAME,
                TagValue::String(Ed2kText::from_utf8("alpha.bin")),
            ),
            tag(FT_FILESIZE, TagValue::U32(1024)),
            tag(FT_SOURCES, TagValue::String(Ed2kText::from_utf8("many"))),
        ],
    );

    assert_skipped_alone(bad, SearchResultSkipReason::TagDecodeFailed);
}

/// A row that stands, named `name`.
fn good_row(hash_byte: u8, name: &str) -> Vec<u8> {
    search_row(
        crate::fixture::hash(hash_byte),
        ClientId::from_u32(0x0100_0090),
        4670,
        vec![
            tag(FT_FILENAME, TagValue::String(Ed2kText::from_utf8(name))),
            tag(FT_FILESIZE, TagValue::U32(2048)),
        ],
    )
}

fn names(decoded: &SearchResults) -> Vec<String> {
    decoded
        .results()
        .iter()
        .map(|result| result.names()[0].to_display_string())
        .collect()
}

/// `bad` between two rows that stand, in a batch that says more is held:
/// the bad row alone is skipped, by `reason`, and the batch keeps the rows on
/// either side and its tail. The bytes are made here, not captured.
fn assert_skipped_alone(bad: Vec<u8>, reason: SearchResultSkipReason) {
    let rows = vec![
        good_row(0x31, "before.bin"),
        bad,
        good_row(0x32, "after.bin"),
    ];
    let mut packet = search_result_packet(rows).payload().to_vec();
    packet.push(0x01);
    let packet = Packet::new(PacketProtocol::Edonkey, 0x33, packet);

    let decoded = SearchResults::try_decode_packet(&packet).expect("the batch stands");
    assert_eq!(names(&decoded), ["before.bin", "after.bin"]);
    assert_eq!(decoded.skipped(), [reason]);
    assert!(decoded.more_available());
}

/// A row whose tag does not decode leaves no way to the next row: the rows
/// before it are kept, as aMule keeps the rows it added before a row threw
/// (`ServerSocket.cpp:608-611`), and what follows is no tail. The bytes are
/// made here, not captured: tag type `0x7F` is no tag type.
#[test]
fn search_results_keep_the_rows_before_a_row_that_does_not_decode() {
    let mut broken = Vec::new();
    broken.extend_from_slice(crate::fixture::hash(0x33).as_bytes());
    broken.extend_from_slice(&0x0100_0091_u32.to_le_bytes());
    broken.extend_from_slice(&4671_u16.to_le_bytes());
    broken.extend_from_slice(&1_u32.to_le_bytes());
    broken.extend_from_slice(&[0x7F, 0x01, 0x00, 0x01, 0x05]);
    let rows = vec![
        good_row(0x34, "before.bin"),
        broken,
        good_row(0x35, "after.bin"),
    ];
    let mut payload = search_result_packet(rows).payload().to_vec();
    payload.push(0x01);
    let packet = Packet::new(PacketProtocol::Edonkey, 0x33, payload);

    let decoded = SearchResults::try_decode_packet(&packet).expect("the batch stands");
    assert_eq!(names(&decoded), ["before.bin"]);
    assert_eq!(decoded.skipped(), [SearchResultSkipReason::TagDecodeFailed]);
    assert!(!decoded.more_available());
}

#[test]
fn search_results_decode_lugdunum_packet_with_more_results_flag() {
    // Captured from local Lugdunum eserver 17.15 in the interop harness:
    // one `shared.bin` result, FT_SOURCES encoded as TAGTYPE_UINT8, an
    // extra uint8 descriptor tag 0x30, and a final 0x00 "more results"
    // flag after the result rows.
    let packet = Packet::new(
        PacketProtocol::Edonkey,
        0x33,
        vec![
            0x01, 0x00, 0x00, 0x00, // row count
            0x8E, 0x30, 0x2D, 0xB5, 0xB8, 0x06, 0xA2, 0x5C, 0x93, 0x85, 0xFC, 0x23, 0xF2, 0x10,
            0x62, 0xD2, // file hash
            0xAC, 0x12, 0x00, 0x03, // client id
            0x36, 0x12, // tcp port
            0x04, 0x00, 0x00, 0x00, // tag count
            0x9A, 0x01, b's', b'h', b'a', b'r', b'e', b'd', b'.', b'b', b'i',
            b'n', // STR10 filename
            0x83, 0x02, 0x00, 0x00, 0x01, 0x00, // u32 size
            0x89, 0x15, 0x01, // u8 source count
            0x89, 0x30, 0x01, // unknown u8 descriptor
            0x00, // more-results flag
        ],
    );

    let decoded = SearchResults::decode_packet(&packet).unwrap();
    let result = &decoded.results()[0];

    assert_eq!(result.primary_name().to_display_string(), "shared.bin");
    assert_eq!(result.file_size(), 65_536);
    assert_eq!(result.reported_availability(), Some(1));
    assert_eq!(
        result.complete_sources(),
        Some(1),
        "the 0x30 byte beside FT_SOURCES is FT_COMPLETE_SOURCES"
    );
    assert_eq!(
        result.file_type(),
        None,
        "a real Lugdunum answer carries no FT_FILETYPE — the Type column has \
         only the extension to work from"
    );
}

#[test]
fn search_results_combines_large_file_size_tags() {
    let packet = search_result_packet(vec![search_row(
        crate::fixture::hash(0xbb),
        ClientId::from_u32(0x0100_0080),
        4663,
        vec![
            tag(
                FT_FILENAME,
                TagValue::String(Ed2kText::from_utf8("large.bin")),
            ),
            tag(FT_FILESIZE, TagValue::U32(5)),
            tag(FT_FILESIZE_HI, TagValue::U16(2)),
        ],
    )]);

    let decoded = SearchResults::decode_packet(&packet).unwrap();
    assert_eq!(decoded.results()[0].file_size(), (2_u64 << 32) | 5);
}

#[test]
fn search_results_skip_alone_a_row_missing_its_file_size() {
    let bad = search_row(
        crate::fixture::hash(0xcc),
        ClientId::from_u32(0x0100_0081),
        4664,
        vec![tag(
            FT_FILENAME,
            TagValue::String(Ed2kText::from_utf8("missing-size.bin")),
        )],
    );

    assert_skipped_alone(bad, SearchResultSkipReason::MissingFileSize);
}

/// aMule drops a row above `MAX_FILE_SIZE` alone (stock 2.3.3
/// `SearchList.cpp:561-570`); rmule names that cause rather than a missing
/// name.
#[test]
fn search_results_skip_alone_a_row_above_the_ed2k_size_limit() {
    let bad = search_row(
        crate::fixture::hash(0xce),
        ClientId::from_u32(0x0100_0083),
        4666,
        vec![
            tag(
                FT_FILENAME,
                TagValue::String(Ed2kText::from_utf8("huge.bin")),
            ),
            tag(FT_FILESIZE, TagValue::U32(u32::MAX)),
            tag(FT_FILESIZE_HI, TagValue::U32(u32::MAX)),
        ],
    );

    assert_skipped_alone(bad, SearchResultSkipReason::FileSizeAboveLimit);
}

/// aMule drops a row of zero bytes alone (stock 2.3.3 `SearchList.cpp:561-569`);
/// the row's bytes are made here, not captured.
#[test]
fn search_results_skip_alone_a_row_of_zero_bytes() {
    let bad = search_row(
        crate::fixture::hash(0xcf),
        ClientId::from_u32(0x0100_0084),
        4667,
        vec![
            tag(
                FT_FILENAME,
                TagValue::String(Ed2kText::from_utf8("empty.bin")),
            ),
            tag(FT_FILESIZE, TagValue::U32(0)),
        ],
    );

    assert_skipped_alone(bad, SearchResultSkipReason::FileSizeZero);
}

#[test]
fn search_results_skip_alone_a_row_missing_its_file_name() {
    let bad = search_row(
        crate::fixture::hash(0xdd),
        ClientId::from_u32(0x0100_0082),
        4665,
        vec![tag(FT_FILESIZE, TagValue::U32(1024))],
    );

    assert_skipped_alone(bad, SearchResultSkipReason::MissingFileName);
}

#[test]
fn search_results_preserves_unknown_well_formed_descriptor_tags() {
    let unknown = tag(
        0xd0,
        TagValue::String(Ed2kText::from_utf8("artist evidence")),
    );
    let packet = search_result_packet(vec![search_row(
        crate::fixture::hash(0xee),
        ClientId::from_u32(0x0100_0083),
        4666,
        vec![
            tag(
                FT_FILENAME,
                TagValue::String(Ed2kText::from_utf8("track.mp3")),
            ),
            tag(FT_FILESIZE, TagValue::U32(2048)),
            tag(FT_FILETYPE, TagValue::String(Ed2kText::from_utf8("Audio"))),
            tag(FT_FILEFORMAT, TagValue::String(Ed2kText::from_utf8("mp3"))),
            unknown.clone(),
        ],
    )]);

    let decoded = SearchResults::decode_packet(&packet).unwrap();
    let result = &decoded.results()[0];

    assert_eq!(result.file_type().unwrap().to_display_string(), "Audio");
    assert_eq!(result.file_format().unwrap().to_display_string(), "mp3");
    assert_eq!(result.extra_tags(), &[unknown]);
}

#[test]
fn server_packet_umbrella_recognizes_search_results() {
    let packet = search_result_packet(vec![search_row(
        crate::fixture::hash(0xab),
        ClientId::from_u32(0x0100_0084),
        4667,
        vec![
            tag(
                FT_FILENAME,
                TagValue::String(Ed2kText::from_utf8("result.bin")),
            ),
            tag(FT_FILESIZE, TagValue::U32(4096)),
        ],
    )]);

    match ServerPacket::decode(&packet).unwrap() {
        ServerPacket::SearchResults(results) => {
            assert_eq!(
                results.results()[0].primary_name().to_display_string(),
                "result.bin"
            );
        }
        other => panic!("expected SearchResults, got {other:?}"),
    }
}

/// Made bytes, not a capture: one row, then a two-byte tail. eMule keeps
/// every row and reads a tail longer than one byte as "no more"
/// (`SearchList.cpp:268-282`); aMule reads no tail on a server's answer
/// (stock 2.3.3 `SearchList.cpp:541-548`).
#[test]
fn a_made_answer_with_a_long_tail_keeps_its_rows_and_says_no_more() {
    let mut packet = search_result_packet(vec![search_row(
        crate::fixture::hash(0xc4),
        ClientId::from_u32(0x0B00_0A0A),
        4711,
        vec![
            tag(
                FT_FILENAME,
                TagValue::String(Ed2kText::from_utf8("kept.mkv")),
            ),
            tag(FT_FILESIZE, TagValue::U32(2048)),
        ],
    )])
    .payload()
    .to_vec();
    packet.extend_from_slice(&[0x01, 0x00]);
    let packet = Packet::new(PacketProtocol::Edonkey, 0x33, packet);

    let decoded = SearchResults::try_decode_packet(&packet).expect("the rows stand");
    assert_eq!(decoded.results().len(), 1);
    assert_eq!(decoded.results()[0].file_hash(), crate::fixture::hash(0xc4));
    assert!(!decoded.more_available());
}
