//! Kad tag lists step past a tag of a type rmule never reads (ADR-0053): an
//! eMule-family storer writes `TAG_KADAICHHASHRESULT` as a `BSOB` into its
//! keyword answers (eMule 0.70b `Entry.cpp:680-710`), and the row, the rest
//! of the answer and every other list still decode. The keyword answer is the
//! one reader that keeps that `BSOB`'s roots (ADR-0038). These datagrams
//! splice a source-derived `BSOB` into rmule's own encodings; no counterparty
//! bytes with the tag are captured yet.

use rmule_kad::keyword_store::{KeywordResultRow, decode_search_key_res, encode_search_key_res};
use rmule_kad::{Kad2Message, Kad2NodeInfo, KadAichRootReport, KadEnvelope, KadId};
use rmule_primitives::AichRootHash;
use rmule_testkit::kad_keyword::{file_id, keyword, name_tag, own_id, size_tag};

/// `TAG_KADAICHHASHRESULT` as eMule writes it: a `BSOB` under the one-byte
/// name `0x37` holding `value`.
fn aich_result_bsob(value: &[u8]) -> Vec<u8> {
    let len = u8::try_from(value.len()).expect("a BSOB value fits its length byte");
    [&[0x0A, 0x01, 0x00, 0x37, len][..], value].concat()
}

/// The `BSOB` value of `<count>{<popularity><AICH root>}` for `pairs`, under
/// the `count` it claims.
fn aich_pairs(count: u8, pairs: &[(u8, u8)]) -> Vec<u8> {
    let mut value = vec![count];
    for &(popularity, fill) in pairs {
        value.push(popularity);
        value.extend_from_slice(&[fill; AichRootHash::BYTE_LEN]);
    }
    value
}

fn root(fill: u8) -> AichRootHash {
    AichRootHash::from_bytes([fill; AichRootHash::BYTE_LEN])
}

/// `envelope` with `tag` spliced in as the first tag of the list whose count
/// byte sits at `count_at`.
fn with_tag(envelope: &KadEnvelope, count_at: usize, tag: &[u8]) -> KadEnvelope {
    let mut payload = envelope.payload().to_vec();
    payload[count_at] += 1;
    payload.splice(count_at + 1..count_at + 1, tag.iter().copied());
    KadEnvelope::plain(envelope.opcode(), payload)
}

fn two_rows() -> Vec<KeywordResultRow> {
    vec![
        KeywordResultRow {
            file_id: file_id(0xD1),
            tags: vec![name_tag("song.mp3"), size_tag(1_024)],
            aich_roots: Vec::new(),
        },
        KeywordResultRow {
            file_id: file_id(0xD2),
            tags: vec![name_tag("other.mp3"), size_tag(2_048)],
            aich_roots: Vec::new(),
        },
    ]
}

/// The answer [`two_rows`] encode to, with `bsob_value` spliced into the
/// first row as its `TAG_KADAICHHASHRESULT`.
fn answer_carrying(bsob_value: &[u8]) -> KadEnvelope {
    let served = encode_search_key_res(own_id(), keyword(), &two_rows());
    // The first row's tag count follows the sender, the keyword, the row count
    // and the row's file ID.
    let count_at = 2 * KadId::BYTE_LEN + 2 + KadId::BYTE_LEN;
    with_tag(&served[0], count_at, &aich_result_bsob(bsob_value))
}

#[test]
fn a_keyword_answer_row_carrying_the_aich_bsob_keeps_its_root_and_every_other_row() {
    let mut expected = two_rows();
    expected[0].aich_roots = vec![KadAichRootReport {
        popularity: 1,
        root: root(0xAB),
    }];

    assert_eq!(
        decode_search_key_res(&answer_carrying(&aich_pairs(1, &[(1, 0xAB)]))),
        Ok(expected)
    );
}

#[test]
fn a_root_no_publisher_reported_is_skipped() {
    let mut expected = two_rows();
    expected[0].aich_roots = vec![KadAichRootReport {
        popularity: 3,
        root: root(0xBC),
    }];

    assert_eq!(
        decode_search_key_res(&answer_carrying(&aich_pairs(2, &[(0, 0xAB), (3, 0xBC)]))),
        Ok(expected)
    );
}

#[test]
fn an_aich_bsob_short_of_its_count_drops_the_roots_not_the_row() {
    assert_eq!(
        decode_search_key_res(&answer_carrying(&aich_pairs(2, &[(4, 0xAB)]))),
        Ok(two_rows())
    );
}

#[test]
fn a_hello_carrying_a_bsob_keeps_its_udp_port_and_misc_options() {
    let info = Kad2NodeInfo {
        id: KadId::from_bytes([0xC1; KadId::BYTE_LEN]),
        tcp_port: 4662,
        version: 8,
        udp_port_tag: Some(4673),
        misc_options: 0x02,
    };
    let hello = Kad2Message::HelloReq(info).encode();
    // The tag count follows the ID, the TCP port and the version byte.
    let count_at = KadId::BYTE_LEN + 2 + 1;

    assert_eq!(
        Kad2Message::decode(&with_tag(
            &hello,
            count_at,
            &aich_result_bsob(&aich_pairs(1, &[(1, 0xAB)]))
        )),
        Ok(Kad2Message::HelloReq(info))
    );
}
