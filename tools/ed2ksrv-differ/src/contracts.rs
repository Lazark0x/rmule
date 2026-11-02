//! The contracts v0.9.85 added whose server half is a plain function: OFFERFILES
//! v1 both ways, and the search that names one file by its hash. The server's
//! own reader and writer stand against rmule's, so a change to the contract on
//! either side reads as a divergence here rather than on a bench.

use bytes::BytesMut;
use ed2k_server::proto::search as their_search;
use ed2k_server::proto::tags::{Tag as TheirTag, TagValue as TheirValue, write_tag_list};
use ed2k_server::server::login::LoginRequest as TheirLogin;
use ed2k_server::server::offer_pacing::{OfferPolicy, client_requests_v1};

use rmule_ed2k::{LoginAdvert, LoginRequest, OfferPace, SearchRequest, ServerFileLimits};
use rmule_primitives::{
    Capabilities, ClientIdentity, CryptStance, Ed2kText, FileHash, KeywordQuery, SearchResult, Tag,
    UserHash,
};

use crate::report::{Origin, Reading, Report, Row, guarded, read};

const SURFACE: &str = "server-contracts";
/// `ST_SOFTFILES`, `ST_HARDFILES`.
const SOFT_ID: u8 = 0x88;
const HARD_ID: u8 = 0x89;
const HASH_HEX: &str = "A1B2C3D4E5F60718293A4B5C6D7E8F90";
const HASH_SIZE: u64 = 700;

pub fn run(report: &mut Report) {
    offer_pace_request(report);
    offer_pace_advert(report);
    named_file_search(report);
}

/// rmule's login, asking: their reader must see a client that asked.
fn offer_pace_request(report: &mut Report) {
    let identity = ClientIdentity::new(
        UserHash::from_bytes([0xAB; UserHash::BYTE_LEN]),
        Ed2kText::from_utf8("rmule-differ"),
        4662,
        60,
    );
    let request = LoginRequest::from_identity_advertising(
        &identity,
        &Capabilities::shipped(CryptStance::new(true, true, false)),
        LoginAdvert {
            offer_pace: true,
            ..LoginAdvert::default()
        },
    );
    let payload = request.encode_packet().payload().to_vec();
    let ours = read([
        ("asks_v1", "true".to_owned()),
        ("tag_count", request.tags().len().to_string()),
    ]);
    let theirs = match guarded(|| TheirLogin::parse(&payload)) {
        Err(panic) => Reading::Panicked(panic),
        Ok(Err(e)) => Reading::Refused(e.to_string()),
        Ok(Ok(parsed)) => read([
            ("asks_v1", client_requests_v1(&parsed.tags).to_string()),
            ("tag_count", parsed.tags.len().to_string()),
        ]),
    };
    report.push(Row {
        surface: SURFACE,
        case: "login/asks-offerfiles-v1".to_owned(),
        origin: Origin::RmuleEmit,
        input: payload,
        rmule: ours,
        ed2ksrv: theirs,
    });
}

/// Their advertisement, in their writer's bytes: rmule must read the numbers
/// the server enforces.
fn offer_pace_advert(report: &mut Report) {
    let policy = OfferPolicy {
        soft: 5_000,
        hard: 7_500,
        batch_max: 150,
        min_interval_ms: 500,
    };
    let mut tags = vec![
        TheirTag::byte(SOFT_ID, TheirValue::U32(policy.soft)),
        TheirTag::byte(HARD_ID, TheirValue::U32(policy.hard)),
    ];
    tags.extend(policy.tags());
    let mut bytes = BytesMut::new();
    write_tag_list(&mut bytes, &tags);
    // `write_tag_list` leads with its count.
    let (count, body) = bytes.split_at(4);
    let count = u32::from_le_bytes(count.try_into().expect("four bytes")) as usize;

    let ours = match Tag::decode_block(body, count) {
        Err(e) => Reading::Refused(e.to_string()),
        Ok((decoded, _)) => {
            let pace = OfferPace::from_ident(&decoded, ServerFileLimits::default());
            read([
                (
                    "negotiated",
                    matches!(pace, OfferPace::Negotiated(_)).to_string(),
                ),
                ("batch", pace.batch().to_string()),
                (
                    "interval_ms",
                    pace.gap_after(pace.batch() as usize)
                        .as_millis()
                        .to_string(),
                ),
                (
                    "budget",
                    pace.new_files_left(0).unwrap_or_default().to_string(),
                ),
            ])
        }
    };
    let theirs = read([
        ("negotiated", "true".to_owned()),
        ("batch", policy.batch_max.to_string()),
        ("interval_ms", policy.min_interval_ms.to_string()),
        ("budget", policy.soft.to_string()),
    ]);
    report.push(Row {
        surface: SURFACE,
        case: "ident/offerfiles-v1-advert".to_owned(),
        origin: Origin::RmuleEmit,
        input: bytes.to_vec(),
        rmule: ours,
        ed2ksrv: theirs,
    });
}

/// Every form, on the bytes rmule sends: the server reads a hash off the same
/// phrases rmule proves by one.
fn named_file_search(report: &mut Report) {
    let lower = HASH_HEX.to_lowercase();
    let cases: [(&str, String); 8] = [
        ("short", format!("ed2k::{HASH_HEX}")),
        ("short-lower-case", format!("ED2K::{lower}")),
        ("short-sized", format!("ed2k:{HASH_SIZE}:{HASH_HEX}")),
        (
            "link",
            format!("ed2k://|file|a.iso|{HASH_SIZE}|{HASH_HEX}|/"),
        ),
        ("magnet", format!("magnet:?xt=urn:ed2k:{HASH_HEX}")),
        (
            "magnet-ed2khash",
            format!("magnet:?xt=urn:ed2khash:{HASH_HEX}"),
        ),
        ("two-words", format!("ed2k::{HASH_HEX} linux")),
        ("short-hash", format!("ed2k::{}", &HASH_HEX[..31])),
    ];
    let mut raw = [0u8; FileHash::BYTE_LEN];
    for (at, byte) in raw.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&HASH_HEX[at * 2..at * 2 + 2], 16).expect("hex");
    }
    let row = SearchResult::new(
        FileHash::from_bytes(raw),
        HASH_SIZE,
        vec![Ed2kText::from_utf8("field-recording.wav")],
        Vec::new(),
    )
    .expect("a row");

    for (case, phrase) in cases {
        let query = KeywordQuery::new(Ed2kText::from_utf8(&phrase)).expect("a phrase");
        let payload = SearchRequest::from_query(query.clone())
            .encode_packet()
            .payload()
            .to_vec();
        let ours = read([("names_file", query.matches(&row).to_string())]);
        let theirs = match guarded(|| their_search::parse(&payload)) {
            Err(panic) => Reading::Panicked(panic),
            Ok(Err(e)) => Reading::Refused(e.to_string()),
            Ok(Ok(node)) => {
                let named = their_search::ed2k_file_search(&node)
                    .is_some_and(|(hash, size)| hash == raw && (size == 0 || size == HASH_SIZE));
                read([("names_file", named.to_string())])
            }
        };
        report.push(Row {
            surface: SURFACE,
            case: format!("search/names-a-file-{case}"),
            origin: Origin::RmuleEmit,
            input: payload,
            rmule: ours,
            ed2ksrv: theirs,
        });
    }
}
