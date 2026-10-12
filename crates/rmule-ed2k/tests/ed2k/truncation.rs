//! A capture cut at any byte must come back as an error or as fewer rows,
//! never as a panic or a short read taken for a whole one: the three decoders
//! that read through the shared bounds-checked reader, fed every prefix of
//! genuine counterparty bytes.

use std::path::Path;

use std::net::{Ipv4Addr, Ipv6Addr};

use rmule_ed2k::{
    FoundSources, OfferFiles, OfferedFile, SearchRequest, SearchResults, ServerGrants, ServerMet,
};
use rmule_primitives::{
    ClientId, Ed2kText, FileHash, Ipv4Endpoint, Ipv6Endpoint, Packet, PeerSource,
};
use rmule_testkit::wire::cut_payload;

fn frame(name: &str) -> Packet {
    Packet::decode_exact(&crate::fixture::captured("search-wire-20260928", name))
        .expect("a whole captured frame")
}

#[test]
fn a_search_request_cut_anywhere_is_an_error() {
    for name in [
        "amule_search_req_joined_0x16.bin",
        "amule_search_req_joined3_0x16.bin",
    ] {
        let whole = frame(name);
        SearchRequest::decode_packet(&whole).expect("the whole request decodes");
        for at in 0..whole.payload().len() {
            assert!(
                SearchRequest::decode_packet(&cut_payload(&whole, at)).is_err(),
                "{name} cut to {at} of {} bytes decoded",
                whole.payload().len()
            );
        }
    }
}

#[test]
fn a_search_answer_cut_anywhere_never_gains_a_row() {
    for name in [
        "lugdunum_search_res_split_0x33.bin",
        "lugdunum_search_res_not_0x33.bin",
        "lugdunum_search_res_or_0x33.bin",
        "lugdunum_related_res_0x33.bin",
        "ed2ksrv_search_res_typetag_0x33.bin",
    ] {
        let whole = frame(name);
        let rows = SearchResults::decode_packet(&whole)
            .expect("the whole answer decodes")
            .results()
            .len();
        assert!(rows > 0, "{name} carries rows");
        for at in 0..whole.payload().len() {
            let Ok(partial) = SearchResults::decode_packet(&cut_payload(&whole, at)) else {
                continue;
            };
            assert!(
                partial.results().len() < rows || at + 1 >= whole.payload().len(),
                "{name} cut to {at} of {} bytes kept all {rows} rows",
                whole.payload().len()
            );
        }
    }
}

#[test]
fn a_server_list_cut_anywhere_reports_the_short_read() {
    let goldens = crate::fixture::capture_dirs(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/server_met/captured"),
        "server.met.bin",
    );
    assert!(!goldens.is_empty(), "a captured server.met is checked in");
    for dir in goldens {
        let bytes = std::fs::read(dir.join("server.met.bin")).expect("read the golden");
        assert!(!ServerMet::decode(&bytes).unwrap().is_truncated());
        // A cut inside the header or the server count reads as an empty list
        // with a declared count of 0 — the documented whole-file posture.
        for at in 5..bytes.len() {
            if let Ok(partial) = ServerMet::decode(&bytes[..at]) {
                assert!(
                    partial.is_truncated(),
                    "{}: a cut to {at} of {} bytes read as whole",
                    dir.display(),
                    bytes.len()
                );
            }
        }
    }
}

#[test]
fn an_offer_cut_anywhere_is_an_error() {
    let files = [
        OfferedFile::new(
            FileHash::from_bytes([0x11; FileHash::BYTE_LEN]),
            42,
            Ed2kText::from_utf8("ab"),
        ),
        OfferedFile::new(
            FileHash::from_bytes([0x22; FileHash::BYTE_LEN]),
            6 << 30,
            Ed2kText::from_utf8("cd"),
        ),
    ];
    let whole = OfferFiles::announce(
        ServerGrants::default(),
        ClientId::from_u32(0x0403_0201),
        ClientId::from_u32(0x0403_0201),
        4662,
        &files,
    )
    .encode_packet();
    OfferFiles::decode_packet(&whole).expect("the whole offer decodes");
    for at in 0..whole.payload().len() {
        assert!(
            OfferFiles::decode_packet(&cut_payload(&whole, at)).is_err(),
            "an offer cut to {at} of {} bytes decoded",
            whole.payload().len()
        );
    }
}

fn high(d: u8) -> PeerSource {
    PeerSource::HighId(Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, d), 4662))
}

#[test]
fn a_classic_source_list_cut_anywhere_is_an_error() {
    let whole = FoundSources::new(FileHash::from_bytes([0x33; 16]), vec![high(1), high(2)])
        .expect("two sources")
        .encode_packet();
    FoundSources::decode_packet(&whole).expect("the whole list decodes");
    for at in 0..whole.payload().len() {
        assert!(
            FoundSources::decode_packet(&cut_payload(&whole, at)).is_err(),
            "a source list cut to {at} of {} bytes decoded",
            whole.payload().len()
        );
    }
}

#[test]
fn a_sentinel_source_list_cut_anywhere_keeps_only_what_precedes_the_sentinel() {
    let v6 = PeerSource::Ipv6(Ipv6Endpoint::new(
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        4662,
    ));
    let whole = FoundSources::new(FileHash::from_bytes([0x44; 16]), vec![high(1), v6, high(3)])
        .expect("three sources")
        .encode_packet();
    assert_eq!(
        FoundSources::decode_packet(&whole).unwrap().sources().len(),
        3
    );
    for at in 0..whole.payload().len() {
        let Ok(partial) = FoundSources::decode_packet(&cut_payload(&whole, at)) else {
            continue;
        };
        assert!(
            partial.tail().is_malformed() && partial.sources().len() <= 1,
            "a list cut to {at} of {} bytes kept {:?} as {:?}",
            whole.payload().len(),
            partial.sources(),
            partial.tail()
        );
    }
}
