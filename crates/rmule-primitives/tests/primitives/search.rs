//! Search as a value type: what a query accepts, what makes two results the
//! same file, how a merge folds names and source counts, and how a result's
//! file class is read from its name and its tag.

use rmule_primitives::{
    ClientId, Ed2kFileClass, Ed2kLink, Ed2kText, FileHash, KeywordQuery, PeerSource, SearchResult,
    SearchResultOrigin, Tag, TagName, TagValue,
};

fn hash(byte: u8) -> FileHash {
    FileHash::from_bytes([byte; FileHash::BYTE_LEN])
}

fn source(id: u32, port: u16) -> PeerSource {
    PeerSource::new(ClientId::from_u32(id), port)
}

#[test]
fn search_query_rejects_blank_phrase() {
    assert!(KeywordQuery::new(Ed2kText::from_utf8("")).is_err());
    assert!(KeywordQuery::new(Ed2kText::from_utf8("   ")).is_err());
    assert!(KeywordQuery::new(Ed2kText::from_utf8("\t\n")).is_err());
}

#[test]
fn search_query_accepts_non_utf8_nonblank_phrase() {
    let query = KeywordQuery::new(Ed2kText::from_bytes(vec![0xff, b'a'])).unwrap();
    assert_eq!(query.phrase().as_bytes(), &[0xff, b'a']);
}

#[test]
fn search_query_stores_optional_filters() {
    let query = KeywordQuery::new(Ed2kText::from_utf8("ubuntu iso"))
        .unwrap()
        .with_file_type(Ed2kFileClass::CdImage)
        .with_min_size(1024)
        .with_max_size(4096)
        .with_min_availability(5)
        .with_extension(Ed2kText::from_utf8("iso"));

    assert_eq!(query.phrase().to_display_string(), "ubuntu iso");
    // The query keeps the class the operator picked; the *wire* fold to "Pro"
    // happens at encode time, so a round-tripped request can still say
    // "CD-image" back to the front-end.
    assert_eq!(query.file_type(), Some(Ed2kFileClass::CdImage));
    assert_eq!(query.min_size(), Some(1024));
    assert_eq!(query.max_size(), Some(4096));
    assert_eq!(query.min_availability(), Some(5));
    assert_eq!(query.extension().unwrap().to_display_string(), "iso");
}

#[test]
fn search_result_requires_at_least_one_name() {
    assert!(
        SearchResult::new(
            hash(0xaa),
            1024,
            Vec::new(),
            vec![source(0x0100_007f, 4662)]
        )
        .is_err()
    );
}

#[test]
fn search_result_key_dedupes_by_hash_and_size() {
    let first = SearchResult::new(
        hash(0xaa),
        1024,
        vec![Ed2kText::from_utf8("first.bin")],
        vec![source(0x0100_007f, 4662)],
    )
    .unwrap();
    let same_key = SearchResult::new(
        hash(0xaa),
        1024,
        vec![Ed2kText::from_utf8("other.bin")],
        Vec::new(),
    )
    .unwrap();
    let different_size = SearchResult::new(
        hash(0xaa),
        2048,
        vec![Ed2kText::from_utf8("first.bin")],
        Vec::new(),
    )
    .unwrap();

    assert_eq!(first.key(), same_key.key());
    assert_ne!(first.key(), different_size.key());
}

#[test]
fn result_merge_preserves_primary_name_and_adds_aliases_without_duplicates() {
    let mut first = SearchResult::new(
        hash(0xaa),
        1024,
        vec![Ed2kText::from_utf8("first.bin")],
        vec![source(0x0100_007f, 4662)],
    )
    .unwrap();
    let second = SearchResult::new(
        hash(0xaa),
        1024,
        vec![
            Ed2kText::from_utf8("other.bin"),
            Ed2kText::from_utf8("first.bin"),
        ],
        vec![source(0x0100_0080, 4663), source(0x0100_007f, 4662)],
    )
    .unwrap();

    first.merge_aliases_from(&second);

    assert_eq!(first.primary_name().to_display_string(), "first.bin");
    assert_eq!(
        first
            .names()
            .iter()
            .map(Ed2kText::to_display_string)
            .collect::<Vec<_>>(),
        vec!["first.bin", "other.bin"]
    );
    assert_eq!(
        first.sources(),
        &[source(0x0100_007f, 4662), source(0x0100_0080, 4663)]
    );
}

#[test]
fn merge_ignores_results_with_different_keys() {
    let mut first = SearchResult::new(
        hash(0xaa),
        1024,
        vec![Ed2kText::from_utf8("first.bin")],
        Vec::new(),
    )
    .unwrap();
    let other = SearchResult::new(
        hash(0xbb),
        1024,
        vec![Ed2kText::from_utf8("other.bin")],
        Vec::new(),
    )
    .unwrap();

    first.merge_aliases_from(&other);

    assert_eq!(
        first
            .names()
            .iter()
            .map(Ed2kText::to_display_string)
            .collect::<Vec<_>>(),
        vec!["first.bin"]
    );
}

#[test]
fn search_result_to_file_link_uses_primary_name_and_no_hash_set() {
    let result = SearchResult::new(
        hash(0xaa),
        1024,
        vec![
            Ed2kText::from_utf8("first.bin"),
            Ed2kText::from_utf8("other.bin"),
        ],
        Vec::new(),
    )
    .unwrap();

    let link = result.to_file_link();

    assert_eq!(link.name.to_display_string(), "first.bin");
    assert_eq!(link.size, 1024);
    assert_eq!(link.file_hash, hash(0xaa));
    assert!(link.part_hash_set.is_none());
    assert!(link.aich_root.is_none());
    assert_eq!(
        Ed2kLink::File(link).to_string(),
        "ed2k://|file|first.bin|1024|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|/"
    );
}

#[test]
fn reported_availability_is_optional_advisory_metadata() {
    let result = SearchResult::new(
        hash(0xaa),
        1024,
        vec![Ed2kText::from_utf8("first.bin")],
        Vec::new(),
    )
    .unwrap();
    assert_eq!(result.reported_availability(), None);

    let result = result.with_reported_availability(17);
    assert_eq!(result.reported_availability(), Some(17));
}

#[test]
fn result_metadata_and_extra_tags_are_preserved() {
    let tag = Tag::new(
        TagName::compact_id(0xd0),
        TagValue::String(Ed2kText::from_utf8("artist")),
    );
    let result = SearchResult::new(
        hash(0xaa),
        1024,
        vec![Ed2kText::from_utf8("track.mp3")],
        Vec::new(),
    )
    .unwrap()
    .with_file_type(Ed2kText::from_utf8("Audio"))
    .with_file_format(Ed2kText::from_utf8("mp3"))
    .with_extra_tags(vec![tag.clone()]);

    assert_eq!(result.file_type().unwrap().to_display_string(), "Audio");
    assert_eq!(result.file_format().unwrap().to_display_string(), "mp3");
    assert_eq!(result.extra_tags(), &[tag]);
}

// ---------------------------------------------------------------------------
// File classification (aMule 2.3.3 `ED2KFileTypesMap`)
// ---------------------------------------------------------------------------

/// One extension per class, plus the shapes that must *not* classify. The
/// table itself is transcribed from `OtherFunctions.cpp:656-894`; this pins
/// that each class is reachable and that the three "no class" shapes stay
/// unclassified instead of guessing.
#[test]
fn extensions_classify_into_the_seven_ed2k_classes() {
    let cases = [
        ("song.mp3", Some(Ed2kFileClass::Audio)),
        ("clip.avi", Some(Ed2kFileClass::Video)),
        ("photo.jpeg", Some(Ed2kFileClass::Image)),
        ("manual.pdf", Some(Ed2kFileClass::Document)),
        ("setup.exe", Some(Ed2kFileClass::Program)),
        ("bundle.rar", Some(Ed2kFileClass::Archive)),
        ("distro.iso", Some(Ed2kFileClass::CdImage)),
        // `.bin` is a CD image in aMule's table, not a program.
        ("alpha.bin", Some(Ed2kFileClass::CdImage)),
        // Case is normalised the way `GetED2KFileTypeID` lowercases first.
        ("HOLIDAY.JPG", Some(Ed2kFileClass::Image)),
        ("README", None),
        ("archive.tar.unknownext", None),
        (".bashrc", None),
    ];

    for (name, expected) in cases {
        assert_eq!(
            Ed2kFileClass::from_file_name(name),
            expected,
            "classifying {name}"
        );
    }
}

/// The two wire vocabularies aMule keeps apart: what a search/publish may say
/// (`GetED2KFileTypeSearchTerm` — archives and CD images ride `"Pro"`) and the
/// internal label that keeps them distinct (`GetFileTypeByName`).
#[test]
fn class_terms_follow_the_two_amule_vocabularies() {
    let rows = [
        (Ed2kFileClass::Audio, "Audio", "Audio"),
        (Ed2kFileClass::Video, "Video", "Video"),
        (Ed2kFileClass::Image, "Image", "Image"),
        (Ed2kFileClass::Document, "Doc", "Doc"),
        (Ed2kFileClass::Program, "Pro", "Pro"),
        (Ed2kFileClass::Archive, "Pro", "Arc"),
        (Ed2kFileClass::CdImage, "Pro", "Iso"),
    ];

    for (class, search_term, internal_term) in rows {
        assert_eq!(class.search_term(), search_term, "search term of {class:?}");
        assert_eq!(
            class.internal_term(),
            internal_term,
            "internal term of {class:?}"
        );
    }
}

#[test]
fn file_type_tags_parse_case_insensitively_and_reject_unknown_terms() {
    assert_eq!(
        Ed2kFileClass::from_type_tag("Audio"),
        Some(Ed2kFileClass::Audio)
    );
    assert_eq!(
        Ed2kFileClass::from_type_tag("video"),
        Some(Ed2kFileClass::Video)
    );
    assert_eq!(
        Ed2kFileClass::from_type_tag(" Iso "),
        Some(Ed2kFileClass::CdImage)
    );
    assert_eq!(Ed2kFileClass::from_type_tag("Collection"), None);
    assert_eq!(Ed2kFileClass::from_type_tag(""), None);
}

/// The Type column's rule: the name's extension — which carries almost every
/// real row, since eserver never emits `FT_FILETYPE` and aMule omits it for
/// files it cannot classify — and the tag only where the name says nothing.
#[test]
fn result_file_class_reads_the_name_first_then_the_tag() {
    let named = SearchResult::new(
        hash(0xaa),
        1024,
        vec![Ed2kText::from_utf8("distro.iso")],
        Vec::new(),
    )
    .unwrap();
    assert_eq!(named.file_class(), Some(Ed2kFileClass::CdImage));

    // The wire term is coarser than the extension: `Pro` covers programs,
    // archives and CD-images alike, so it must not demote a known `.iso`.
    let tagged = named.clone().with_file_type(Ed2kText::from_utf8("Pro"));
    assert_eq!(tagged.file_class(), Some(Ed2kFileClass::CdImage));

    // An extension-less name is exactly where the tag earns its place.
    let unnamed = SearchResult::new(
        hash(0xbb),
        1024,
        vec![Ed2kText::from_utf8("live-set-2003")],
        Vec::new(),
    )
    .unwrap();
    assert_eq!(unnamed.file_class(), None);
    assert_eq!(
        unnamed
            .clone()
            .with_file_type(Ed2kText::from_utf8("Audio"))
            .file_class(),
        Some(Ed2kFileClass::Audio)
    );
    assert_eq!(
        unnamed
            .with_file_type(Ed2kText::from_utf8("EmuleCollection"))
            .file_class(),
        None,
        "an unknown term classifies nothing"
    );
}

// ---------------------------------------------------------------------------
// Merge semantics (aMule `CSearchFile::MergeResults`)
// ---------------------------------------------------------------------------

fn counted(availability: u32, complete: u32, origin: SearchResultOrigin) -> SearchResult {
    SearchResult::new(
        hash(0xaa),
        1024,
        vec![Ed2kText::from_utf8("distro.iso")],
        Vec::new(),
    )
    .unwrap()
    .with_reported_availability(availability)
    .with_complete_sources(complete)
    .with_origin(origin)
}

/// Two servers answering for the same file each counted their own logged-in
/// peers, so the counts add (`SearchFile.cpp:148`).
#[test]
fn two_server_reports_of_one_file_add_their_source_counts() {
    let mut first = counted(40, 5, SearchResultOrigin::Ed2kServer);
    first.merge_aliases_from(&counted(2, 1, SearchResultOrigin::Ed2kServer));

    assert_eq!(first.reported_availability(), Some(42));
    assert_eq!(first.complete_sources(), Some(6));
}

/// Every Kad storer republishes the same global count, so a second answer is
/// corroboration, not addition (`SearchFile.cpp:145`).
#[test]
fn kad_reports_of_one_file_keep_the_highest_count() {
    let mut first = counted(40, 5, SearchResultOrigin::Kad);
    first.merge_aliases_from(&counted(42, 3, SearchResultOrigin::Kad));

    assert_eq!(first.reported_availability(), Some(42));
    assert_eq!(first.complete_sources(), Some(5));
    assert_eq!(first.origin(), SearchResultOrigin::Kad);
}

/// rmule merges both producers into one result set, which aMule never does.
/// A mixed pair takes the safe side: a global Kad figure is never added onto a
/// per-server one, and the row stays marked Kad so a third report folds the
/// same way.
#[test]
fn a_mixed_server_and_kad_report_folds_by_max_and_stays_kad() {
    let mut server_first = counted(40, 5, SearchResultOrigin::Ed2kServer);
    server_first.merge_aliases_from(&counted(90, 7, SearchResultOrigin::Kad));
    assert_eq!(server_first.reported_availability(), Some(90));
    assert_eq!(server_first.origin(), SearchResultOrigin::Kad);

    server_first.merge_aliases_from(&counted(3, 1, SearchResultOrigin::Ed2kServer));
    assert_eq!(
        server_first.reported_availability(),
        Some(90),
        "a later server report must not be added onto a Kad global count"
    );
}

/// A counted row absorbing a count-less one (and the reverse) keeps whichever
/// figure exists — the merge must never blank a known count.
#[test]
fn merging_with_a_countless_report_keeps_the_known_count() {
    let bare = SearchResult::new(
        hash(0xaa),
        1024,
        vec![Ed2kText::from_utf8("distro.iso")],
        Vec::new(),
    )
    .unwrap();

    let mut counted_first = counted(9, 2, SearchResultOrigin::Ed2kServer);
    counted_first.merge_aliases_from(&bare);
    assert_eq!(counted_first.reported_availability(), Some(9));
    assert_eq!(counted_first.complete_sources(), Some(2));

    let mut bare_first = bare;
    bare_first.merge_aliases_from(&counted(9, 2, SearchResultOrigin::Ed2kServer));
    assert_eq!(bare_first.reported_availability(), Some(9));
    assert_eq!(bare_first.complete_sources(), Some(2));
}

fn named(name: &str, size: u64) -> SearchResult {
    SearchResult::new(
        hash(0xcd),
        size,
        vec![Ed2kText::from_utf8(name)],
        Vec::new(),
    )
    .unwrap()
}

fn query(phrase: &str) -> KeywordQuery {
    KeywordQuery::new(Ed2kText::from_utf8(phrase)).unwrap()
}

/// Search Attribution's keyword reading (ADR-0034): every word of
/// the query — split where aMule or ed2k-server split — a whole word of one
/// name, folded by case and accent, as both bench servers read it (runs
/// 1790603580 and 1790604060).
#[test]
fn a_row_proves_the_keywords_when_every_token_is_inside_one_name() {
    let row = named("Ubuntu-22.04_Desktop.iso", 1024);
    assert!(query("ubuntu desktop").matches(&row));
    assert!(query("UBUNTU 22.04").matches(&row), "split on the dot too");
    assert!(
        !query("buntu desk").matches(&row),
        "a substring is no whole word: neither server matched `betaga` in `alphabetagamma`"
    );
    assert!(
        !query("ubuntu server").matches(&row),
        "every token is required"
    );
    assert!(
        query("café").matches(&named("cafe.mp3", 1))
            && query("cafe").matches(&named("Café.mp3", 1)),
        "accents fold both ways, as Lugdunum folds them"
    );

    let aliased = named("first.iso", 1024).with_origin(SearchResultOrigin::Kad);
    let mut merged = aliased.clone();
    merged.merge_aliases_from(
        &SearchResult::new(
            hash(0xcd),
            1024,
            vec![Ed2kText::from_utf8("debian netinst.iso")],
            Vec::new(),
        )
        .unwrap(),
    );
    assert!(query("debian").matches(&merged), "any of the row's names");
}

/// A row proves a constraint only with the field in hand; the server's own
/// answer keeps a row unless a field it carries says otherwise.
#[test]
fn an_absent_field_proves_nothing_and_contradicts_nothing() {
    let floor = query("live").with_min_availability(5);
    let silent = named("live-set", 1024);
    assert!(!floor.matches(&silent));
    assert!(!floor.contradicts(&silent));
    let sparse = silent.clone().with_reported_availability(2);
    assert!(!floor.matches(&sparse));
    assert!(floor.contradicts(&sparse));
    assert!(floor.matches(&silent.with_reported_availability(9)));

    let video = query("live").with_file_type(Ed2kFileClass::Video);
    let untyped = named("live-set-2003", 1024);
    assert!(!video.matches(&untyped));
    assert!(!video.contradicts(&untyped));
    assert!(video.contradicts(&named("live.mp3", 1024)));
    assert!(video.matches(&named("live.avi", 1024)));

    let avi = query("live").with_extension(Ed2kText::from_utf8(".AVI"));
    assert!(
        !avi.contradicts(&untyped),
        "no extension, no format: unknown"
    );
    assert!(avi.contradicts(&named("live.mkv", 1)));
    assert!(avi.matches(&named("live.avi", 1)));
}

#[test]
fn size_bounds_are_inclusive_and_always_decidable() {
    let bounded = query("a").with_min_size(10).with_max_size(20);
    assert!(bounded.matches(&named("a", 10)));
    assert!(bounded.matches(&named("a", 20)));
    assert!(bounded.contradicts(&named("a", 9)));
    assert!(bounded.contradicts(&named("a", 21)));
}

/// The predicate reads the words the query sends: an explicit `AND` is
/// the join, not a keyword, and a quoted run's words each must be inside a
/// name — the same terms the server was asked for.
#[test]
fn a_row_proves_the_words_the_query_sends() {
    let row = named("Rock_n_Roll.Live.At.Wembley.1986.mkv", 1024);
    assert!(query("rock AND roll").matches(&row));
    assert!(
        !query("rock and roll").matches(&row),
        "a lower-case and is a word"
    );
    assert!(query(r#""at wembley" 1986"#).matches(&row));
    assert!(!query(r#""at wembley" 1987"#).matches(&row));
}

/// A quoted run is an ordered phrase, as Lugdunum reads it (run 1790603580:
/// `"sepspace spaceword"` found `sepspace spaceword.bin`, the reverse found
/// nothing): its words in order, side by side, in one name.
#[test]
fn a_quoted_run_proves_only_as_an_ordered_phrase() {
    let row = named("Live.At.Wembley.1986.mkv", 1024);
    assert!(query(r#""at wembley""#).matches(&row));
    assert!(!query(r#""wembley at""#).matches(&row), "order holds");
    assert!(!query(r#""live wembley""#).matches(&row), "side by side");
    assert!(
        query("wembley at").matches(&row),
        "unquoted words need no order"
    );
}
