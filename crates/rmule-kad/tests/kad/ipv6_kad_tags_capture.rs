//! Kad's `ip6` tag (ADR-0087) from kno's aMule at its Fork Pin `ab483654`,
//! both directions (interop flow `ipv6-kad-tags`, run `1790199666`):
//! kno's own source publish, and the `0x3B` it answered with
//! after storing ours.
//!
//! And `bi6` (run `1790216063`): kno's packed `0x3B`
//! re-serving the tag a firewalled rmule publisher wrote.
//!
//! And a second `ip6` writer (run `1790251066`): emule-qt
//! `73fff714`'s source publish, obfuscated to the storer's Kad ID, spelling
//! its address in lower case.
//!
//! Every assertion reads kno's bytes; rmule's own `0x44` is kept beside them
//! only as the Stimulus the re-serve is checked against. Provenance, image
//! digests and the preconditions each frame needed are in each `meta.toml`.

use std::net::{Ipv4Addr, Ipv6Addr};

use rmule_kad::{
    Kad2Message, KadDecoded, KadEnvelope, KadPublishedSource, decode_exact, decode_source_result,
};
use rmule_primitives::{FileHashSummary, Ipv4Endpoint, PeerSource, kad_wire_id};

use crate::fixture::{AMULE_TCP_PORT, KAD_PROTO};

const FIXTURE_DIR: &str = "fixtures/ipv6/captured/amule-kno-ab483654-kad-ip6-20260923/";
const BI6_FIXTURE_DIR: &str = "fixtures/ipv6/captured/amule-kno-ab483654-kad-bi6-20260924/";
const EMULEQT_FIXTURE_DIR: &str = "fixtures/ipv6/captured/emule-qt-73fff714-kad-ip6-20260924/";

/// kno's address on the dialect WAN — the one an inbound IPv6 dial verified.
const KNO_IPV6: Ipv6Addr = Ipv6Addr::new(0x3fff, 0x0ed2, 1, 0, 0, 0, 0, 2);
/// The rmule publisher's addresses and its advertised IPv6.
const PUBLISHER_IP: Ipv4Addr = Ipv4Addr::new(45, 55, 200, 8);
const PUBLISHER_IPV6: Ipv6Addr = Ipv6Addr::new(0x3fff, 0x0ed2, 1, 0, 0, 0, 0, 8);
/// kno's Kad and client UDP port — also what it indexed as ours.
const BODY_UDP_PORT: u16 = 4672;
/// kno's user hash as it loaded it: the harness pinned `0x4B` × 16 and aMule
/// stamped bytes 5 and 14 (`Preferences.cpp:1081-1082`).
const KNO_USER_HASH: [u8; 16] = [
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x0E, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x6F, 0x4B,
];
/// The `ip6` tag's header: string type, three-byte name, 32 characters.
const IP6_TAG_HEADER: [u8; 8] = [0x02, 0x03, 0x00, b'i', b'p', b'6', 0x20, 0x00];
/// The `bi6` tag's header, the same shape.
const BI6_TAG_HEADER: [u8; 8] = [0x02, 0x03, 0x00, b'b', b'i', b'6', 0x20, 0x00];
/// The firewalled publisher's address: the buddy row's own `SOURCEIP`.
const FW_PUBLISHER_IP: Ipv4Addr = Ipv4Addr::new(45, 55, 200, 7);
/// emule-qt's IPv6 on the dialect WAN, the one its interface carries.
const EMULEQT_IPV6: Ipv6Addr = Ipv6Addr::new(0x3fff, 0x0ed2, 1, 0, 0, 0, 0, 0xa);

fn frame(name: &str) -> Vec<u8> {
    crate::fixture::captured(FIXTURE_DIR, name)
}

fn plain(datagram: &[u8]) -> KadEnvelope {
    let KadDecoded::Plain(envelope) = decode_exact(datagram).expect("a well-formed datagram")
    else {
        panic!("the bench ran every body crypt-off");
    };
    envelope
}

/// The Kad key of a **Synthetic File** (`byte = offset % 251`) of `len` bytes,
/// the files the flow shared and published.
fn synthetic_file_key(len: usize) -> [u8; 16] {
    let bytes: Vec<u8> = (0..len).map(|offset| (offset % 251) as u8).collect();
    kad_wire_id(*FileHashSummary::digest_bytes(&bytes).file_hash().as_bytes())
}

/// The 40-byte `ip6` tag in `frame`, by its header.
fn ip6_tag(frame: &[u8]) -> &[u8] {
    string_tag(frame, &IP6_TAG_HEADER)
}

/// The 40-byte 32-character string tag `header` opens in `frame`.
fn string_tag<'a>(frame: &'a [u8], header: &[u8; 8]) -> &'a [u8] {
    let at = frame
        .windows(header.len())
        .position(|window| window == header)
        .expect("the frame carries the tag");
    &frame[at..at + header.len() + 32]
}

/// kno's own source publish: a High-ID row for the file it shares, with the
/// verified IPv6 as the last tag, and rmule's publish decoder reads all of it.
#[test]
fn amule_knos_publish_carries_its_verified_ipv6_and_rmule_reads_it() {
    let f = frame("amule_kno_publish_source_req_0x44.bin");
    assert_eq!(f[..2], [KAD_PROTO, 0x44]);

    let Kad2Message::PublishSourceReq {
        file,
        source_id,
        source,
    } = Kad2Message::decode(&plain(&f)).expect("rmule's codec reads kno's publish")
    else {
        panic!("0x44 decodes to a publish");
    };
    assert_eq!(*file.as_bytes(), synthetic_file_key(1 << 20));
    assert_eq!(source_id, kad_wire_id(KNO_USER_HASH));
    assert_eq!(
        source,
        KadPublishedSource {
            source_type: Some(1),
            tcp_port: Some(AMULE_TCP_PORT),
            udp_port_tag: None,
            file_size: Some(1 << 20),
            encryption: Some(0),
            ipv6: Some(KNO_IPV6),
            buddy: None,
        },
    );
    // `CSearch::StorePacket` appends `ip6` after `ENCRYPTION` (`Search.cpp:899`),
    // so it is the frame's tail.
    assert_eq!(ip6_tag(&f), &f[f.len() - 40..]);
}

/// kno spells the address the way `CMD4Hash::Encode` spells a hash — upper
/// case — where rmule, at this capture, wrote lower case (it writes upper case
/// now). The spec's case-insensitive reader rule is what lets the
/// two meet; this is the frame that shows they have to.
#[test]
fn amule_kno_writes_the_ip6_hex_upper_case() {
    let theirs = frame("amule_kno_publish_source_req_0x44.bin");
    let ours = frame("rmule_publish_source_req_0x44.bin");
    assert_eq!(&ip6_tag(&theirs)[8..], b"3FFF0ED2000100000000000000000002");
    assert_eq!(&ip6_tag(&ours)[8..], b"3fff0ed2000100000000000000000008");
}

/// kno stored our `ip6` untouched and served it back beside the tags it
/// authored itself, and rmule's source-row projection reads the answer as a
/// High-ID source carrying the IPv6 endpoint.
#[test]
fn amule_kno_re_serves_our_ip6_verbatim_in_its_search_answer() {
    let ours = frame("rmule_publish_source_req_0x44.bin");
    let answer = frame("amule_kno_search_res_0x3b.bin");
    assert_eq!(answer[..2], [KAD_PROTO, 0x3B]);
    assert_eq!(
        ip6_tag(&answer),
        ip6_tag(&ours),
        "the storer path indexes unrecognised tags verbatim (KademliaUDPListener.cpp:1402)",
    );

    let rows = decode_source_result(&plain(&answer)).expect("rmule reads kno's answer");
    let [row] = rows.as_slice() else {
        panic!("one published source, one row: {rows:?}");
    };
    assert_eq!(
        row.peer_source(),
        Some(PeerSource::HighId(Ipv4Endpoint::new(
            PUBLISHER_IP,
            AMULE_TCP_PORT
        ))),
    );
    let facts = row.facts().expect("a decoded row carries its facts");
    assert_eq!(
        facts.ipv6.map(|endpoint| (endpoint.ip, endpoint.port)),
        Some((PUBLISHER_IPV6, AMULE_TCP_PORT)),
    );
    // SOURCEIP and SOURCEUPORT are kno's own: the observed sender, and the
    // port it indexed because the publisher named none.
    assert_eq!(
        facts.kad_udp,
        Some(Ipv4Endpoint::new(PUBLISHER_IP, BODY_UDP_PORT))
    );
    assert_eq!(
        answer[2..18],
        synthetic_file_key(2 << 20),
        "kno answered from its own Kad ID, pinned at the key it answered for",
    );
}

/// kno stored our firewalled row's `bi6` untouched and served it back. Two
/// rows pass aMule's 200-byte packing line, so the answer is a packed `0xE5`
/// datagram; rmule inflates it and reads the `bi6` into the row's buddy
/// contact — it names the buddy, not the file's holder, so the row is no
/// direct source of any family.
#[test]
fn amule_kno_re_serves_our_bi6_verbatim_in_a_packed_answer() {
    let ours = crate::fixture::captured(
        BI6_FIXTURE_DIR,
        "rmule_firewalled_publish_source_req_0x44.bin",
    );
    let answer = crate::fixture::captured(BI6_FIXTURE_DIR, "amule_kno_search_res_bi6_0x3b.bin");
    assert_eq!(answer[..2], [0xE5, 0x3B], "kno packed its two-row answer");
    let KadDecoded::Packed(envelope) = decode_exact(&answer).expect("rmule inflates kno's answer")
    else {
        panic!("a 0xE5 datagram decodes as packed");
    };
    assert_eq!(
        string_tag(&envelope.encode(), &BI6_TAG_HEADER),
        string_tag(&ours, &BI6_TAG_HEADER),
        "the storer path indexes unrecognised tags verbatim (KademliaUDPListener.cpp:1402)",
    );

    let rows = decode_source_result(&envelope).expect("rmule reads kno's answer");
    assert_eq!(rows.len(), 2, "the buddy row and the direct row: {rows:?}");
    let buddy_row = rows
        .iter()
        .find(|row| row.facts().is_some_and(|facts| facts.source_type == 3))
        .expect("the firewalled publisher's type-3 row");
    assert_eq!(buddy_row.peer_source(), None);
    let facts = buddy_row.facts().expect("a decoded row carries its facts");
    assert_eq!(
        facts.ipv6, None,
        "bi6 never becomes the row's own IPv6 half"
    );
    assert_eq!(
        facts.kad_udp,
        Some(Ipv4Endpoint::new(FW_PUBLISHER_IP, BODY_UDP_PORT))
    );
    let buddy = facts.buddy.expect("a type-3 row names its buddy");
    assert_eq!(buddy.buddy_ipv6, Some(PUBLISHER_IPV6));
    assert_eq!(
        buddy.buddy_udp,
        Some(Ipv4Endpoint::new(PUBLISHER_IP, BODY_UDP_PORT))
    );
}

/// emule-qt writes its `ip6` in lower case (`QByteArray::toHex`,
/// `KadSearch.cpp:1386-1391`) — the spelling kno's upper-case frame above does
/// not exercise — inside a datagram obfuscated to the storer's Kad ID, which
/// is pinned at the file's key. rmule decrypts it with that ID and its publish
/// decoder reads the lower-case string into the row's IPv6.
#[test]
fn emule_qts_lower_case_ip6_reads_into_the_rows_ipv6() {
    let wire = crate::fixture::captured(
        EMULEQT_FIXTURE_DIR,
        "emuleqt_publish_source_req_0x44_obfuscated.bin",
    );
    let file_key = synthetic_file_key(3 << 19);
    let f = rmule_primitives::decrypt_datagram_client(
        &wire,
        &rmule_primitives::ClientDecryptKeys {
            kad_id: Some(&file_key),
            ..Default::default()
        },
    )
    .expect("the datagram is keyed to the storer's Kad ID")
    .payload;
    assert_eq!(f[..2], [KAD_PROTO, 0x44]);
    assert_eq!(&ip6_tag(&f)[8..], b"3fff0ed200010000000000000000000a");

    let Kad2Message::PublishSourceReq { file, source, .. } =
        Kad2Message::decode(&plain(&f)).expect("rmule's codec reads emule-qt's publish")
    else {
        panic!("0x44 decodes to a publish");
    };
    assert_eq!(*file.as_bytes(), file_key);
    assert_eq!(source.source_type, Some(1));
    assert_eq!(source.tcp_port, Some(AMULE_TCP_PORT));
    assert_eq!(source.ipv6, Some(EMULEQT_IPV6));
}
