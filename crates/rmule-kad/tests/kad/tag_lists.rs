//! Kad tag lists step past a tag of a type rmule never reads (ADR-0053): an
//! eMule-family storer writes `TAG_KADAICHHASHRESULT` as a `BSOB` into its
//! keyword answers (emule-qt `KadEntry.cpp:504-527`), and the row, the rest of
//! the answer and every other list still decode. These datagrams splice a
//! source-derived `BSOB` into rmule's own encodings; no counterparty bytes
//! with the tag are captured yet.

use rmule_kad::keyword_store::{KeywordResultRow, decode_search_key_res, encode_search_key_res};
use rmule_kad::{Kad2Message, Kad2NodeInfo, KadEnvelope, KadId};
use rmule_testkit::kad_keyword::{file_id, keyword, name_tag, own_id, size_tag};

/// `TAG_KADAICHHASHRESULT` as eMule writes it: a `BSOB` under the one-byte
/// name `0x37`, one (popularity, AICH hash) pair.
fn aich_result_bsob() -> Vec<u8> {
    let mut tag = vec![0x0A, 0x01, 0x00, 0x37, 21, 0x01];
    tag.extend_from_slice(&[0xAB; 20]);
    tag
}

/// `envelope` with the `BSOB` spliced in as the first tag of the list whose
/// count byte sits at `count_at`.
fn with_bsob(envelope: &KadEnvelope, count_at: usize) -> KadEnvelope {
    let mut payload = envelope.payload().to_vec();
    payload[count_at] += 1;
    payload.splice(count_at + 1..count_at + 1, aich_result_bsob());
    KadEnvelope::plain(envelope.opcode(), payload)
}

#[test]
fn a_keyword_answer_row_carrying_the_aich_bsob_decodes_with_every_other_row() {
    let rows = vec![
        KeywordResultRow {
            file_id: file_id(0xD1),
            tags: vec![name_tag("song.mp3"), size_tag(1_024)],
        },
        KeywordResultRow {
            file_id: file_id(0xD2),
            tags: vec![name_tag("other.mp3"), size_tag(2_048)],
        },
    ];
    let served = encode_search_key_res(own_id(), keyword(), &rows);
    // The first row's tag count follows the sender, the keyword, the row count
    // and the row's file ID.
    let count_at = 2 * KadId::BYTE_LEN + 2 + KadId::BYTE_LEN;
    let answer = with_bsob(&served[0], count_at);

    assert_eq!(
        decode_search_key_res(&answer),
        Ok(rows),
        "the BSOB is stepped past, not kept, and fails nothing"
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
        Kad2Message::decode(&with_bsob(&hello, count_at)),
        Ok(Kad2Message::HelloReq(info))
    );
}
