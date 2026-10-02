//! Server-TCP: rmule's encoders against the oracle's pure parse entry points.
//!
//! Every reader used here is a `pub fn` over a byte slice with no server state
//! behind it, so this whole surface runs in microseconds and is exactly
//! reproducible. That is the half of the oracle worth the dependency: the
//! acceptance boundary of a second, independent implementation, evaluated on the
//! bytes rmule really puts on the wire.
//!
//! Directions covered:
//!
//! * **rmule emits → they consume** — the frames rmule's session actually sends
//!   a server, minted here by the production encoders, plus the two
//!   client→server frames a promoted fixture recorded off the live wire.
//! * **they emit → rmule consumes** — thin, and honestly so: their reply
//!   builders (`build_welcome_batch`, `handle_get_sources`, …) all take
//!   `&ServerState` and write into a socket, so there is no pure emitter to call.
//!   Their server→client bytes reach rmule through captured fixtures instead,
//!   which the ed2k crate already asserts on; re-reading them here would add a
//!   second copy of an existing golden, not a second opinion.

use bytes::BytesMut;
use ed2k_server::proto::frame::Ed2kCodec;
use ed2k_server::proto::search as their_search;
use ed2k_server::server::get_sources::GetSourcesRequest as TheirGetSources;
use ed2k_server::server::login::LoginRequest as TheirLogin;
use ed2k_server::server::offerfiles::parse_offerfiles;
use tokio_util::codec::Decoder;

use rmule_ed2k::{GetSourcesRequest, LoginRequest, OfferFiles, OfferedFile, SearchRequest};
use rmule_primitives::{
    Capabilities, ClientId, ClientIdentity, CryptStance, Ed2kText, FileHash, Packet,
    PacketProtocol, KeywordQuery, SourceLookupTarget, Tag, TagValue, UserHash,
};

use crate::report::{Origin, Reading, Report, Row, guarded, hex, read};

/// The one string reading of a tag value both sides can be compared on.
fn tag_text(tags: &[Tag], id: u8) -> String {
    tags.iter()
        .find(|t| t.name().id() == Some(id))
        .and_then(|t| match t.value() {
            TagValue::String(text) => Some(text.to_display_string()),
            _ => None,
        })
        .unwrap_or_else(|| "<none>".to_owned())
}

/// A tag's integer value widened to `u64`, matching how the oracle's `as_u32`
/// promotes its narrow variants. Non-integer values (a string, a raw hash) read
/// as zero, as the oracle reads them.
fn tag_uint(tags: &[Tag], id: u8) -> Option<u64> {
    tags.iter()
        .find(|t| t.name().id() == Some(id))
        .map(|t| match t.value() {
            TagValue::U64(v) => *v,
            TagValue::U32(v) => u64::from(*v),
            TagValue::U16(v) => u64::from(*v),
            TagValue::U8(v) => u64::from(*v),
            TagValue::String(_) | TagValue::Hash(_) => 0,
        })
}

const SURFACE: &str = "server-tcp";

/// Directory holding the promoted captures both implementations were scored
/// against. Resolved from the manifest so the differ works from any cwd.
fn fixture_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/rmule-ed2k/tests/fixtures/server/captured")
}

pub fn run(report: &mut Report) {
    framing(report);
    login(report);
    login_below_rmules_floor(report);
    offer_files(report);
    get_sources(report);
    search_request(report);
    captured_client_frames(report);
}

/// A stable identity so the report diffs to nothing between runs.
fn identity() -> ClientIdentity {
    ClientIdentity::new(
        UserHash::from_bytes([0x5a; 16]),
        Ed2kText::from_utf8("rmule-differ"),
        4662,
        0x3c,
    )
}

fn file_hash(fill: u8) -> FileHash {
    FileHash::from_bytes([fill; 16])
}

// ── framing ─────────────────────────────────────────────────────────────────

/// `0xE3` framing. rmule writes `[proto][len u32 LE][opcode][payload]`, they
/// read the same six-byte header — the layer everything else rides, so a
/// disagreement here would invalidate every row below it.
fn framing(report: &mut Report) {
    let packet = Packet::new(PacketProtocol::Edonkey, 0x16, b"framing probe".to_vec());
    let wire = packet.encode();

    let theirs = guarded(|| {
        let mut codec = Ed2kCodec::new(1_000_000);
        let mut buf = BytesMut::from(&wire[..]);
        codec.decode(&mut buf).map(|frame| (frame, buf.len()))
    });

    let their_reading = match theirs {
        Err(panic) => Reading::Panicked(panic),
        Ok(Err(e)) => Reading::Refused(e.to_string()),
        Ok(Ok((None, _))) => Reading::Refused("codec wants more bytes".to_owned()),
        Ok(Ok((Some(frame), leftover))) => read([
            ("opcode", format!("0x{:02x}", frame.opcode)),
            ("payload", hex(&frame.payload)),
            ("leftover", leftover.to_string()),
        ]),
    };

    let ours = match Packet::decode(&wire) {
        Ok((decoded, consumed)) => read([
            ("opcode", format!("0x{:02x}", decoded.opcode())),
            ("payload", hex(decoded.payload())),
            ("leftover", (wire.len() - consumed).to_string()),
        ]),
        Err(e) => Reading::Refused(e.to_string()),
    };

    report.push(Row {
        surface: SURFACE,
        case: "framing/e3-plain".to_owned(),
        origin: Origin::RmuleEmit,
        input: wire,
        rmule: ours,
        ed2ksrv: their_reading,
    });
}

// ── OP_LOGINREQUEST 0x01 ────────────────────────────────────────────────────

/// The production login: `LoginRequest::from_identity` is what the eD2k session
/// puts on the wire, tag order and all.
fn login(report: &mut Report) {
    let capabilities = Capabilities::shipped(CryptStance::new(true, true, false));
    let request = LoginRequest::from_identity(&identity(), &capabilities);
    let packet = request.encode_packet();
    let payload = packet.payload().to_vec();

    let ours = read([
        ("user_hash", hex(request.user_hash().as_bytes())),
        ("claimed_id", request.client_id().as_u32().to_string()),
        ("port", request.tcp_port().to_string()),
        ("tag_count", request.tags().len().to_string()),
        ("nick", tag_text(request.tags(), 0x01)),
        (
            "server_flags",
            format!("0x{:08x}", tag_uint(request.tags(), 0x20).unwrap_or(0)),
        ),
    ]);

    let theirs = match guarded(|| TheirLogin::parse(&payload)) {
        Err(panic) => Reading::Panicked(panic),
        Ok(Err(e)) => Reading::Refused(e.to_string()),
        Ok(Ok(parsed)) => read([
            ("user_hash", hex(&parsed.user_hash)),
            ("claimed_id", parsed.claimed_id.to_string()),
            ("port", parsed.port.to_string()),
            ("tag_count", parsed.tags.len().to_string()),
            ("nick", parsed.nick().unwrap_or("<none>").to_owned()),
            ("server_flags", format!("0x{:08x}", parsed.server_flags())),
        ]),
    };

    report.push(Row {
        surface: SURFACE,
        case: "login/production-4-tags".to_owned(),
        origin: Origin::RmuleEmit,
        input: payload,
        rmule: ours,
        ed2ksrv: theirs,
    });
}

/// A 22-byte login body: the shortest their own length check admits.
///
/// Outside rmule's emit space — rmule's encoder always writes the tag count, and
/// its decoder refuses anything under 26 bytes — but *inside* theirs, because
/// `login.rs:33-37` has an explicit branch for "payload shorter than 26 ⇒ no tag
/// count". Probed for exactly that reason: an implementation that writes a
/// tolerance branch is claiming the input is reachable.
fn login_below_rmules_floor(report: &mut Report) {
    let mut payload = vec![0x5a; 16];
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&4662u16.to_le_bytes());
    debug_assert_eq!(payload.len(), 22);

    let ours = match LoginRequest::decode_packet(&Packet::new(
        PacketProtocol::Edonkey,
        0x01,
        payload.clone(),
    )) {
        Ok(_) => read([("outcome", "accepted".to_owned())]),
        Err(e) => Reading::Refused(e.to_string()),
    };

    let theirs = match guarded(|| TheirLogin::parse(&payload)) {
        Err(panic) => Reading::Panicked(panic),
        Ok(Err(e)) => Reading::Refused(e.to_string()),
        Ok(Ok(parsed)) => read([("tag_count", parsed.tags.len().to_string())]),
    };

    report.push(Row {
        surface: SURFACE,
        case: "login/22-byte-body-no-tag-count".to_owned(),
        origin: Origin::Boundary,
        input: payload,
        rmule: ours,
        ed2ksrv: theirs,
    });
}

// ── OP_OFFERFILES 0x15 ──────────────────────────────────────────────────────

fn offer_files(report: &mut Report) {
    // Boring filenames on purpose: every record this server indexes runs through
    // a hardcoded content filter that cannot be switched off (audit §6), and a
    // filtered record is dropped in silence.
    let files = [
        OfferedFile::new(
            file_hash(0x11),
            4_096,
            Ed2kText::from_utf8("rmule-bench-fixture-01.bin"),
        ),
        OfferedFile::new(
            file_hash(0x22),
            6_000_000_000,
            Ed2kText::from_utf8("Linux Mint 22.iso"),
        ),
    ];
    let offer = OfferFiles::announce(ClientId::from_u32(0), 4662, &files);
    let packet = offer.encode_packet();
    let payload = packet.payload().to_vec();

    let ours = Reading::Read(
        offer
            .entries()
            .iter()
            .enumerate()
            .flat_map(|(i, entry)| {
                // rmule splits a >4 GiB size across FT_FILESIZE (low u32) and
                // FT_FILESIZE_HI; the comparable reading is the size the two
                // tags reconstruct, which is what their parser builds too.
                let low = tag_uint(entry.tags(), 0x02).unwrap_or_default();
                let high = tag_uint(entry.tags(), 0x3a).unwrap_or_default();
                [
                    (format!("file{i}.hash"), hex(entry.file_hash().as_bytes())),
                    (format!("file{i}.size"), ((high << 32) | low).to_string()),
                    (format!("file{i}.name"), tag_text(entry.tags(), 0x01)),
                ]
            })
            .collect(),
    );

    let theirs = match guarded(|| parse_offerfiles(&payload)) {
        Err(panic) => Reading::Panicked(panic),
        Ok(Err(e)) => Reading::Refused(e.to_string()),
        Ok(Ok(parsed)) => Reading::Read(
            parsed
                .iter()
                .enumerate()
                .flat_map(|(i, f)| {
                    [
                        (format!("file{i}.hash"), hex(&f.hash)),
                        (format!("file{i}.size"), f.size.to_string()),
                        (format!("file{i}.name"), f.filename.clone()),
                    ]
                })
                .collect(),
        ),
    };

    report.push(Row {
        surface: SURFACE,
        case: "offerfiles/two-records-small-and-large".to_owned(),
        origin: Origin::RmuleEmit,
        input: payload,
        rmule: ours,
        ed2ksrv: theirs,
    });
}

// ── OP_GETSOURCES 0x19 ──────────────────────────────────────────────────────

fn get_sources(report: &mut Report) {
    let cases = [
        (
            "getsources/legacy-16-byte",
            GetSourcesRequest::Legacy {
                file_hash: file_hash(0x31),
            },
            None,
        ),
        (
            "getsources/v2-32bit-size",
            GetSourcesRequest::Normal {
                target: SourceLookupTarget::new(file_hash(0x32), 4_096),
            },
            Some(4_096u64),
        ),
        (
            // 6 GiB: past u32, so rmule takes the large form — the only shape
            // that reaches their (hi, lo) read.
            "getsources/v2-large-6gib",
            GetSourcesRequest::Large {
                target: SourceLookupTarget::new(file_hash(0x33), 6 * 1024 * 1024 * 1024),
            },
            Some(6 * 1024 * 1024 * 1024),
        ),
    ];

    for (case, request, intended_size) in cases {
        let packet = request.encode_packet();
        let payload = packet.payload().to_vec();
        let hash = match request {
            GetSourcesRequest::Legacy { file_hash } => file_hash,
            GetSourcesRequest::Normal { target } | GetSourcesRequest::Large { target } => {
                target.file_hash()
            }
        };

        let ours = read([
            ("file_hash", hex(hash.as_bytes())),
            (
                "file_size",
                intended_size.map_or_else(|| "<none>".to_owned(), |s| s.to_string()),
            ),
        ]);

        let theirs = match guarded(|| TheirGetSources::parse(&payload)) {
            Err(panic) => Reading::Panicked(panic),
            Ok(Err(e)) => Reading::Refused(e.to_string()),
            Ok(Ok(parsed)) => read([
                ("file_hash", hex(&parsed.file_hash)),
                (
                    "file_size",
                    parsed
                        .size
                        .map_or_else(|| "<none>".to_owned(), |s| s.to_string()),
                ),
            ]),
        };

        report.push(Row {
            surface: SURFACE,
            case: case.to_owned(),
            origin: Origin::RmuleEmit,
            input: payload,
            rmule: ours,
            ed2ksrv: theirs,
        });
    }
}

// ── OP_SEARCHREQUEST 0x16 ───────────────────────────────────────────────────

/// The search tree is the one TCP body where the two sides hold genuinely
/// different data models — rmule keeps a flat `KeywordQuery`, they keep a
/// recursive `SearchNode` — so the comparable readings are the terms recovered
/// and, for the filters, whether the tree still *decides* the same way. Feeding
/// their `evaluate` two probe files is what makes the filter rows non-vacuous.
fn search_request(report: &mut Report) {
    let cases: [(&str, KeywordQuery); 2] = [
        (
            "search/two-word-phrase",
            KeywordQuery::new(Ed2kText::from_utf8("linux mint")).expect("non-blank search phrase"),
        ),
        (
            "search/phrase-with-min-size",
            KeywordQuery::new(Ed2kText::from_utf8("linux mint"))
                .expect("non-blank search phrase")
                .with_min_size(1_000_000),
        ),
    ];

    for (case, query) in cases {
        let request = SearchRequest::from_query(query.clone());
        let packet = request.encode_packet();
        let payload = packet.payload().to_vec();

        // Two probe files that straddle the min-size filter, so an ignored
        // filter shows up as a changed verdict rather than as nothing.
        let below = ("linux mint 22 iso", 500_000u64);
        let above = ("linux mint 22 iso", 5_000_000u64);
        let rmule_admits = |size: u64| query.min_size().is_none_or(|min| size > min);

        let ours = read([
            ("terms", query.phrase().to_display_string()),
            ("admits_500k", rmule_admits(below.1).to_string()),
            ("admits_5m", rmule_admits(above.1).to_string()),
        ]);

        let theirs = match guarded(|| their_search::parse(&payload)) {
            Err(panic) => Reading::Panicked(panic),
            Ok(Err(e)) => Reading::Refused(e.to_string()),
            Ok(Ok(node)) => read([
                ("terms", their_search::collect_terms(&node).join(" ")),
                (
                    "admits_500k",
                    their_search::evaluate(&node, below.0, below.1).to_string(),
                ),
                (
                    "admits_5m",
                    their_search::evaluate(&node, above.0, above.1).to_string(),
                ),
            ]),
        };

        report.push(Row {
            surface: SURFACE,
            case: case.to_owned(),
            origin: Origin::RmuleEmit,
            input: payload,
            rmule: ours,
            ed2ksrv: theirs,
        });
    }
}

// ── captured client→server frames ───────────────────────────────────────────

/// The rmule-emitted frames a promoted fixture recorded off the live wire, fed
/// back through their parser.
///
/// These are the strongest corpus entries available: not a frame the differ
/// *believes* rmule emits, but the exact bytes a capture run observed leaving
/// it. `OP_GETSERVERLIST 0x14` has an empty body and no parser on their side
/// (`connection.rs:510-513` answers it directly), so it is carried as a framing
/// check only.
fn captured_client_frames(report: &mut Report) {
    let cases: [(&str, &str, u8); 2] = [
        (
            "captured/callback-request-0x1c",
            "ed2ksrv-callback-relay-20260802/callback_request_0x1c.bin",
            0x1c,
        ),
        (
            "captured/get-server-list-0x14",
            "ed2ksrv-serverlist-20260802/get_server_list_0x14.bin",
            0x14,
        ),
    ];

    for (case, relative, expected_opcode) in cases {
        let path = fixture_dir().join(relative);
        let Ok(wire) = std::fs::read(&path) else {
            report.push(Row {
                surface: SURFACE,
                case: case.to_owned(),
                origin: Origin::Fixture,
                input: Vec::new(),
                rmule: Reading::Unreachable(format!("fixture not readable: {}", path.display())),
                ed2ksrv: Reading::Unreachable("no input".to_owned()),
            });
            continue;
        };

        // A drifted fixture is a harness precondition failure, not a decoder
        // disagreement — a SKIP row keeps the rest of the report alive where a
        // panic would lose it (the same reason the oracle runs under
        // `guarded`), while the reason stays visible in CASES.
        if wire.get(5) != Some(&expected_opcode) {
            report.push(Row {
                surface: SURFACE,
                case: case.to_owned(),
                origin: Origin::Fixture,
                input: wire,
                rmule: Reading::Unreachable(format!(
                    "fixture {relative} no longer carries opcode 0x{expected_opcode:02x} — \
                     re-promote it or rename the case"
                )),
                ed2ksrv: Reading::Unreachable("fixture drifted".to_owned()),
            });
            continue;
        }

        let ours = match Packet::decode_exact(&wire) {
            Ok(packet) => read([
                ("opcode", format!("0x{:02x}", packet.opcode())),
                ("payload", hex(packet.payload())),
            ]),
            Err(e) => Reading::Refused(e.to_string()),
        };

        let theirs = match guarded(|| {
            let mut codec = Ed2kCodec::new(1_000_000);
            let mut buf = BytesMut::from(&wire[..]);
            codec.decode(&mut buf)
        }) {
            Err(panic) => Reading::Panicked(panic),
            Ok(Err(e)) => Reading::Refused(e.to_string()),
            Ok(Ok(None)) => Reading::Refused("codec wants more bytes".to_owned()),
            Ok(Ok(Some(frame))) => read([
                ("opcode", format!("0x{:02x}", frame.opcode)),
                ("payload", hex(&frame.payload)),
            ]),
        };

        report.push(Row {
            surface: SURFACE,
            case: case.to_owned(),
            origin: Origin::Fixture,
            input: wire,
            rmule: ours,
            ed2ksrv: theirs,
        });
    }
}
