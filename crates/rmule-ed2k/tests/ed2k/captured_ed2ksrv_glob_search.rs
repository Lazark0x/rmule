//! A genuine **global UDP search answer** — `OP_GLOBSEARCHRES 0x99` — from
//! `andrey23127/ed2k-server` @ `eacf7f1`, drawn by rmule's `OP_GLOBSEARCHREQ
//! 0x98` against a live index that had one matching, sourced file (ed2ksrv
//! capture, 2026-08-02).
//!
//! Both halves of this exchange were **ADR-0045-EXEMPT**: Lugdunum
//! won't answer a `0x98` at all, and eNode implements a `0x99` handler but
//! crashes on the login its precondition needs — so no admissible counterparty
//! had ever produced the frame. This server serves the leg end to end, and the
//! bytes below are the first `0x99` any bench run has held. Per ADR-0045
//! point 2 the same datagram is also the emit row's evidence: the `0x99` *is*
//! the counterparty's observable reaction to rmule's `0x98`.
//!
//! Provenance, the offered file and the exact commands live in `meta.toml`.

use std::net::Ipv4Addr;

use rmule_ed2k::{GlobSearchRes, GlobServStatRes};
use rmule_primitives::FileHash;

/// The file the bench client shared and the search had to find: a boring ASCII
/// name, because the server's L2 content filter is hardcoded-on and drops a
/// matching offer in silence.
const FILE_NAME: &str = "alpha.bin";
const FILE_SIZE: u64 = 256_000;
const FILE_HASH_HEX: &str = "07AACB7384C3C321683145613EABD4A9";

fn decode_search() -> GlobSearchRes {
    GlobSearchRes::decode_udp(&load("search_res_0x99_0.bin")).expect("decode genuine 0x99")
}

/// One packet slice of the `ed2ksrv-glob-search-20260802` capture.
fn load(name: &str) -> Vec<u8> {
    crate::fixture::captured("ed2ksrv-glob-search-20260802", name)
}

/// The headline: the genuine `0x99` decodes into rmule's typed projection with
/// the counterparty's actual index row in it — the file identity the search
/// matched, at full fidelity. A `0x99` that decoded to an empty result list
/// would prove nothing (the shape is already covered by the crate's own unit
/// tests), so the hash, name and size are all pinned.
#[test]
fn decodes_genuine_ed2ksrv_search_answer_with_the_offered_file() {
    let res = decode_search();
    let results = res.results();
    assert_eq!(
        results.len(),
        1,
        "this server packs exactly one result per datagram (udp.rs:1263-1348)"
    );
    let row = &results[0];

    assert_eq!(
        row.file_hash(),
        FileHash::from_hex(FILE_HASH_HEX).expect("fixture hash literal"),
        "the answer must identify the file the bench client actually shared"
    );
    assert_eq!(row.file_size(), FILE_SIZE, "FT_FILESIZE");
    assert_eq!(
        row.primary_name().as_bytes(),
        FILE_NAME.as_bytes(),
        "FT_FILENAME — carried in the compact STR9 tag form"
    );
}

/// The source row the answer carries. This is the substance of a *search*
/// answer as opposed to a bare index lookup: the server reports how many
/// sources it holds for the file, and rmule projects that availability.
#[test]
fn genuine_search_answer_reports_the_live_source_count() {
    let res = decode_search();
    let row = &res.results()[0];
    assert_eq!(
        row.reported_availability(),
        Some(1),
        "FT_SOURCES — the one logged-in client that was offering the file. The \
         server skips zero-source files entirely (udp.rs:1299-1301), so a live \
         source is the precondition this capture had to stage."
    );
    assert_eq!(
        row.complete_sources(),
        Some(1),
        "FT_COMPLETE_SOURCES — the second count every search answer carries \
         (`83 30 01 00 00 00` at the end of the datagram); the sharer held the \
         whole file, so it counts as complete."
    );
    assert_eq!(
        row.file_type(),
        None,
        "no FT_FILETYPE is ever emitted (audit §`0x98`→`0x99`), so the app has \
         to classify `alpha.bin` from its name alone"
    );
}

/// The advertised source endpoint, pinned because it is a **documented
/// divergence** and not the shape a reader would predict. The sharer held a
/// LowID, yet the `0x99` advertises it by its **real address** rather than by
/// the assigned low id that the TCP `OP_FOUNDSOURCES 0x42` path uses
/// (`get_sources.rs:114-117` vs `udp.rs:619-622`, audit deviation §4.4).
///
/// The assertion exists so that divergence stays visible: if a future re-pin of
/// the server converges the two paths, this test says so instead of the
/// difference quietly disappearing from the record.
#[test]
fn source_row_advertises_the_real_address_not_the_assigned_low_id() {
    let res = decode_search();
    let row = &res.results()[0];
    let sources = row.sources();
    assert_eq!(sources.len(), 1, "one source row");

    let id = sources[0]
        .client_id()
        .expect("a classic record names a client id");
    assert!(
        !id.is_low_id(),
        "the UDP path advertises the sharer's real address ({}), even though the \
         sharer itself held a LowID — the audit §4.4 divergence from the TCP 0x42 path",
        id.as_u32()
    );
    assert_eq!(
        id.as_u32(),
        u32::from_le_bytes(Ipv4Addr::new(203, 0, 113, 1).octets()),
        "the sharer's server-observed source address"
    );
}

/// The control leg from the same run: a plain `0x96` status ping answered
/// before the search. It proves the server's UDP surface was live and that the
/// index it answered from held the file — so an empty search answer would have
/// been a real negative, not a dead listener.
#[test]
fn status_control_leg_shows_the_index_held_the_file() {
    let res =
        GlobServStatRes::decode_udp(&load("status_res_0x97.bin")).expect("decode control 0x97");
    assert_eq!(
        res.files(),
        1,
        "the index held exactly the one shared file when the 0x98 went out"
    );
    assert_eq!(
        res.users(),
        1,
        "exactly the one logged-in sharer, which is the source the answer reports"
    );
    assert_eq!(
        res.low_id_users(),
        Some(1),
        "and that single sharer held a LowID — which is what makes the real \
         address in the search answer's source row a genuine divergence rather \
         than an ordinary High-ID row"
    );
}
