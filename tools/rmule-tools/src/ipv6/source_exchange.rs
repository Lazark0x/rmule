//! `rmule-tools ipv6 hold-slot` and `rmule-tools ipv6 sx-ask` — the two rmule
//! bodies `ipv6-extsx` needs around one emule-qt.
//!
//! emule-qt `73fff714` answers a source ask for a **complete shared file** out
//! of the clients it is serving that file to (`KnownFile::createSrcInfoPacket`,
//! `m_uploadingClients`, filtered to `Uploading`/`OnUploadQueue`), and on the
//! ExtSX path it keeps a Low-ID client that named a reachable IPv6 in its hello
//! (`KnownFile.cpp:849`) and writes that address as `CT_MOD_IP_V6`
//! (`KnownFile.cpp:937`). So the carrier half needs a *queued requester* that
//! advertised an IPv6 — `hold-slot` — and a second requester that asks for
//! sources inside the `0xA4` bundle — `sx-ask`. What `sx-ask` exists to obtain
//! is emule-qt's own `OP_ANSWERSOURCES2`, retained byte-exact beside its row;
//! everything either row says about rmule is Stimulus (ADR-0045).
//!
//! The bundle's `0x58` sub carries the asker's part status at rmule's claim of
//! extended-requests 1, which is what an aMule-family answerer needs to serve
//! a complete file (run `1790222202`).

use std::net::Ipv6Addr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Args;
use rmule_net::peer::{ConnectOptions as PeerConnectOptions, Connection as PeerConnection};
use rmule_peer::{
    AnswerSources, AnswerSources2, ConnectionEvent, MiscOptions1, PartBitmap, PartRanges,
    PeerCommand, PeerEvent, PeerHandshakeContext, RequesterCommand, RequesterEvent,
};
use rmule_primitives::{
    ClientId, ClientIdentity, Ed2kFileLink, Ed2kLink, Ed2kText, Ipv4Endpoint, Packet,
    PacketProtocol, UserHash,
};

use crate::capture::{hex_lower, write_new};
use crate::driver_row::Row;
use crate::operand::{parse_peer_endpoint, parse_user_hash};

/// `OP_MULTIPACKET_EXT` — the bundle the source ask rides in.
const OP_MULTIPACKET_EXT: u8 = 0xA4;
/// `OP_ANSWERSOURCES2` — the frame the capture is cut at.
const OP_ANSWERSOURCES2: u8 = 0x84;
/// `OP_ANSWERSOURCES` — the SX1 answer, for an answerer that speaks no SX2.
const OP_ANSWERSOURCES: u8 = 0x82;
/// The ExtSX answer's pinned version byte (ADR-0087).
const EXT_SX_VERSION: u8 = 1;
/// How much of the file the queued requester asks for: one block. The slot is
/// the point, not the bytes, and a request that finished the file would let
/// the counterparty close the slot before the ask lands.
const HOLD_RANGE_BYTES: u64 = 10_240;
/// The inflate cap for a packed answer: far above any source list one body
/// could hold, far below anything a hostile length could exhaust.
const PACKED_INFLATE_CAP: usize = 1 << 20;

/// The operands both bodies share.
#[derive(Debug, Args)]
pub(crate) struct SxBodyArgs {
    /// The emule-qt body, `[addr]:port` or `a.b.c.d:port`.
    #[arg(long)]
    peer: String,
    /// The ed2k link of the file the body shares.
    #[arg(long)]
    file: String,
    /// Our Known IPv6 for this hello's `CT_MOD_IP_V6`. For `hold-slot` it is
    /// the address the counterparty is expected to hand out.
    #[arg(long)]
    advertise_ipv6: Option<Ipv6Addr>,
    /// Our 16-byte user hash as hex. The two bodies need distinct ones: the
    /// counterparty keys its client list by hash.
    #[arg(long)]
    user_hash: String,
    /// The Client ID the hello carries — zero, a client with no server session.
    #[arg(long, default_value_t = 0)]
    client_id: u32,
    /// The server the hello names as ours, `a.b.c.d:port` — what a counterparty
    /// writes as the source's `CT_EMULE_SERVERIP`/`SERVERTCP` beside a Low ID.
    /// Omitted, the hello names none.
    #[arg(long)]
    connected_server: Option<std::net::SocketAddrV4>,
    /// The TCP port the hello advertises.
    #[arg(long, default_value_t = 4662)]
    tcp_port: u16,
    /// Directory for the connection's capture artifacts.
    #[arg(long)]
    capture: PathBuf,
    /// Where to write the row.
    #[arg(long)]
    out: PathBuf,
    /// TCP connect budget, seconds.
    #[arg(long, default_value_t = 10)]
    connect_timeout: u64,
    /// Diagnostic: claim this extended-requests version instead of rmule's
    /// `1`. A queued requester that holds nothing claims `0`, so an
    /// aMule-family answerer lists it as a source of unknown status rather
    /// than dropping it as holding no part the asker lacks.
    #[arg(long)]
    extended_requests: Option<u8>,
}

/// `ipv6 hold-slot`.
#[derive(Debug, Args)]
pub(crate) struct Ipv6HoldSlotArgs {
    #[command(flatten)]
    body: SxBodyArgs,
    /// How long to hold the link after it opened.
    #[arg(long, default_value_t = 60)]
    hold_secs: u64,
}

/// `ipv6 sx-ask`.
#[derive(Debug, Args)]
pub(crate) struct Ipv6SxAskArgs {
    #[command(flatten)]
    body: SxBodyArgs,
    /// How long to wait for the source answer after the bundle went out.
    #[arg(long, default_value_t = 20)]
    response_timeout: u64,
}

/// Printed once the counterparty granted or queued the slot — the harness
/// waits on it before it lets the second body ask.
const SLOT_MARKER: &str = "rmule-ipv6-hold-slot-open";

fn file_link(raw: &str) -> Result<Ed2kFileLink> {
    match Ed2kLink::parse(raw).with_context(|| format!("parse ed2k link {raw}"))? {
        Ed2kLink::File(file) => Ok(file),
        _ => bail!("--file must be an ed2k file link, got {raw}"),
    }
}

async fn connect(body: &SxBodyArgs) -> Result<PeerConnection> {
    let peer = parse_peer_endpoint(&body.peer)?;
    let identity = ClientIdentity::new(
        UserHash::from_bytes(parse_user_hash(&body.user_hash)?),
        Ed2kText::from_utf8("rmule-tools"),
        body.tcp_port,
        60,
    );
    let ctx = PeerHandshakeContext {
        identity,
        client_id: ClientId::from_u32(body.client_id),
        ed2k_client_id: ClientId::from_u32(body.client_id),
        public_ip: None,
        connected_server: body
            .connected_server
            .map(|server| Ipv4Endpoint::new(*server.ip(), server.port())),
    };
    let options = PeerConnectOptions {
        capture_dir: Some(body.capture.clone()),
        connect_timeout: Duration::from_secs(body.connect_timeout),
        ipv6: body.advertise_ipv6,
        extended_requests_capture_override: body.extended_requests,
        ..Default::default()
    };
    Ok(PeerConnection::connect(peer, ctx, options).await?)
}

/// Queue on the counterparty for the shared file and hold the link.
///
/// # Errors
/// If an operand does not parse or the row cannot be written. A counterparty
/// that never opens a slot is a row, not an error.
pub(crate) async fn run_hold_slot(args: Ipv6HoldSlotArgs) -> Result<()> {
    let file = file_link(&args.body.file)?;
    let ranges = PartRanges::new([(0, file.size.min(HOLD_RANGE_BYTES)), (0, 0), (0, 0)])
        .context("first block range")?;
    let mut identified = false;
    let mut slot = String::new();
    let mut received = 0u64;
    let mut failure = String::new();
    match connect(&args.body).await {
        Err(error) => failure = error.to_string(),
        Ok(mut conn) => {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(args.hold_secs);
            loop {
                let event = tokio::select! {
                    () = tokio::time::sleep_until(deadline) => break,
                    event = conn.next_event() => event,
                };
                match event {
                    Some(PeerEvent::Connection(ConnectionEvent::Identified { .. }))
                        if !identified =>
                    {
                        identified = true;
                        let _ = conn
                            .send(PeerCommand::Requester(RequesterCommand::ProbeFile {
                                file_hash: file.file_hash,
                                file_size: file.size,
                                own_status: PartBitmap::downloader_empty(file.size),
                            }))
                            .await;
                    }
                    Some(PeerEvent::Requester(RequesterEvent::FileProbed { status, .. })) => {
                        println!("file_probed: {status:?}");
                        let _ = conn
                            .send(PeerCommand::Requester(RequesterCommand::RequestParts {
                                file_hash: file.file_hash,
                                file_size: file.size,
                                ranges,
                            }))
                            .await;
                    }
                    Some(
                        event @ (PeerEvent::Requester(RequesterEvent::SlotGranted { .. })
                        | PeerEvent::Requester(RequesterEvent::QueueRanked { .. })),
                    ) => {
                        if slot.is_empty() {
                            slot = if matches!(
                                event,
                                PeerEvent::Requester(RequesterEvent::SlotGranted { .. })
                            ) {
                                "granted".to_owned()
                            } else {
                                "queued".to_owned()
                            };
                            println!("{SLOT_MARKER} slot={slot}");
                        }
                        println!("{event}");
                    }
                    Some(PeerEvent::Requester(RequesterEvent::PartReceived { bytes, .. })) => {
                        received = received.saturating_add(bytes.len() as u64);
                    }
                    Some(PeerEvent::Connection(ConnectionEvent::Disconnected { reason })) => {
                        failure = format!("{reason:?}");
                        break;
                    }
                    Some(event) => println!("{event}"),
                    None => break,
                }
            }
            let _ = conn.shutdown().await;
        }
    }
    let mut row = Row::new(
        "rmule-tools ipv6 hold-slot — a requester queued on the counterparty for\n\
         its shared file, holding the link while a second body asks it for\n\
         sources. Stimulus about rmule throughout.",
    );
    row.str("peer", &args.body.peer)
        .str(
            "advertised_ipv6",
            &args
                .body
                .advertise_ipv6
                .map(|a| a.to_string())
                .unwrap_or_default(),
        )
        .str("user_hash", &args.body.user_hash.to_uppercase())
        .bool("identified", identified)
        .str("slot", &slot)
        .int("bytes_received", i64::try_from(received).unwrap_or(-1))
        .str("failure", &failure);
    crate::driver_row::write_row(&args.body.out, row)
}

/// What the counterparty's answer said, read off its own bytes.
#[derive(Default)]
struct AnswerFacts {
    bundle_hex: String,
    answer_bytes: usize,
    answer_file: String,
    answer_hex: String,
    answer_protocol: String,
    answer_opcode: String,
    sx_version: i64,
    record_count: i64,
    records: Vec<String>,
    ipv6_sources: Vec<String>,
    decode_error: String,
}

/// Ask the counterparty for sources inside the `0xA4` bundle and retain its
/// answer.
///
/// # Errors
/// If an operand does not parse or the row cannot be written. A counterparty
/// that answers nothing is a row with `answer_bytes = 0`.
pub(crate) async fn run_sx_ask(args: Ipv6SxAskArgs) -> Result<()> {
    let file = file_link(&args.body.file)?;
    let mut identified = false;
    let mut peer_sx1_version = 0u8;
    let mut event_note = String::new();
    let mut session_sources = Vec::new();
    let mut failure = String::new();
    match connect(&args.body).await {
        Err(error) => failure = error.to_string(),
        Ok(mut conn) => {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(args.response_timeout);
            loop {
                let event = tokio::select! {
                    () = tokio::time::sleep_until(deadline) => break,
                    event = conn.next_event() => event,
                };
                match event {
                    Some(PeerEvent::Connection(ConnectionEvent::Identified { identity }))
                        if !identified =>
                    {
                        identified = true;
                        peer_sx1_version = MiscOptions1::from_tags(identity.unknown_tags())
                            .map_or(0, MiscOptions1::source_exchange_version);
                        let command = PeerCommand::Requester(RequesterCommand::RequestFile {
                            file_hash: file.file_hash,
                            file_size: file.size,
                            own_status: PartBitmap::downloader_empty(file.size),
                            want_sources: true,
                            want_aich_root: false,
                        });
                        let _ = conn.send(command).await;
                    }
                    Some(PeerEvent::Requester(RequesterEvent::SourcesReceived {
                        sources, ..
                    })) => {
                        event_note = format!("SourcesReceived {} rows", sources.len());
                        session_sources = sources
                            .iter()
                            .map(|source| {
                                source.as_peer_endpoint().map_or_else(
                                    || format!("{:?}", source.peer_source()),
                                    |e| e.to_string(),
                                )
                            })
                            .collect();
                        break;
                    }
                    Some(PeerEvent::Requester(RequesterEvent::SourceExchangeAnswerSkipped {
                        reason,
                    })) => {
                        event_note = format!("SourceExchangeAnswerSkipped {reason}");
                        break;
                    }
                    Some(PeerEvent::Connection(ConnectionEvent::Disconnected { reason })) => {
                        failure = format!("{reason:?}");
                        break;
                    }
                    Some(event) => println!("{event}"),
                    None => break,
                }
            }
            let _ = conn.shutdown().await;
        }
    }
    let facts = read_answer(&args.body.capture, peer_sx1_version)?;
    println!(
        "ipv6-sx-ask identified={identified} answer_bytes={} ipv6_sources={:?}",
        facts.answer_bytes, facts.ipv6_sources
    );
    let mut row = Row::new(
        "rmule-tools ipv6 sx-ask — the counterparty's own OP_ANSWERSOURCES2 to a\n\
         source ask inside the 0xA4 bundle, read through rmule's ExtSX reader\n\
         (ADR-0087). Stimulus about rmule; the retained frame is the evidence.",
    );
    row.str("peer", &args.body.peer)
        .str("file_hash", &file.file_hash.to_hex_upper())
        .bool("identified", identified)
        .int("peer_sx1_version", i64::from(peer_sx1_version))
        .str("failure", &failure)
        .str("session_event", &event_note)
        .list("session_sources", &session_sources)
        .str("bundle_hex", &facts.bundle_hex)
        .int(
            "answer_bytes",
            i64::try_from(facts.answer_bytes).unwrap_or(-1),
        )
        .str("answer_file", &facts.answer_file)
        .str("answer_hex", &facts.answer_hex)
        .str("answer_protocol", &facts.answer_protocol)
        .str("answer_opcode", &facts.answer_opcode)
        .int("sx_version", facts.sx_version)
        .int("record_count", facts.record_count)
        .list("records", &facts.records)
        .list("ipv6_sources", &facts.ipv6_sources)
        .str("decode_error", &facts.decode_error);
    crate::driver_row::write_row(&args.body.out, row)
}

/// Cut the bundle rmule sent and the answer the counterparty sent out of the
/// capture, retain the answer, and decode it. An SX1 `0x82` answer has no
/// version byte, so it is read at the answerer's own claimed SX1 nibble, the
/// way aMule reads one (`uClientSXVersion`).
fn read_answer(capture: &std::path::Path, peer_sx1_version: u8) -> Result<AnswerFacts> {
    let mut facts = AnswerFacts::default();
    if let Ok(outbound) = std::fs::read(capture.join("outbound.bin"))
        && let Some(bundle) = crate::ipv6::first_frame(
            &outbound,
            PacketProtocol::Emule.as_byte(),
            OP_MULTIPACKET_EXT,
        )
    {
        facts.bundle_hex = hex_lower(bundle);
    }
    let Ok(inbound) = std::fs::read(capture.join("inbound.bin")) else {
        return Ok(facts);
    };
    let frame = [OP_ANSWERSOURCES2, OP_ANSWERSOURCES]
        .into_iter()
        .flat_map(|opcode| {
            [PacketProtocol::Emule, PacketProtocol::PackedEd2k].map(|proto| (proto, opcode))
        })
        .find_map(|(proto, opcode)| {
            crate::ipv6::first_frame(&inbound, proto.as_byte(), opcode).map(|f| (opcode, f))
        });
    let Some((opcode, frame)) = frame else {
        return Ok(facts);
    };
    let path = capture.join(if opcode == OP_ANSWERSOURCES2 {
        "answersources2.bin"
    } else {
        "answersources.bin"
    });
    write_new(&path, frame)?;
    facts.answer_bytes = frame.len();
    facts.answer_file = path.display().to_string();
    facts.answer_hex = hex_lower(frame);

    let packet = Packet::decode_exact(frame).context("the answer is a whole frame")?;
    facts.answer_protocol = format!("{:?}", packet.protocol());
    facts.answer_opcode = format!("0x{opcode:02X}");
    let packet = if packet.protocol() == PacketProtocol::PackedEd2k {
        match rmule_primitives::inflate(&packet, PACKED_INFLATE_CAP, PacketProtocol::Emule) {
            Ok(plain) => plain,
            Err(reason) => {
                facts.decode_error = format!("inflate: {reason:?}");
                return Ok(facts);
            }
        }
    } else {
        packet
    };
    let decoded = if opcode == OP_ANSWERSOURCES {
        facts.sx_version = i64::from(peer_sx1_version);
        AnswerSources::decode_packet(&packet, peer_sx1_version)
            .map(|answer| answer.sources)
            .map_err(|error| error.to_string())
    } else {
        facts.sx_version = packet.payload().first().map_or(-1, |v| i64::from(*v));
        if packet.payload().first() == Some(&EXT_SX_VERSION) {
            AnswerSources2::decode_ext_packet(&packet)
        } else {
            AnswerSources2::decode_packet(&packet)
        }
        .map(|answer| answer.sources)
        .map_err(|error| error.to_string())
    };
    match decoded {
        Err(error) => facts.decode_error = error,
        Ok(sources) => {
            facts.record_count = i64::try_from(sources.len()).unwrap_or(-1);
            for entry in &sources {
                let ipv6 = entry.ipv6().map(|e| e.to_string()).unwrap_or_default();
                facts.records.push(format!(
                    "wire_id=0x{:08X} port={} ipv6={ipv6} user_hash={} crypt={}",
                    entry
                        .source()
                        .peer_source()
                        .map_or(0, rmule_primitives::PeerSource::wire_id),
                    entry.tcp_port(),
                    entry
                        .user_hash()
                        .map(|h| h.to_hex_upper())
                        .unwrap_or_default(),
                    entry
                        .crypt_options()
                        .map(|c| format!("0x{:02X}", c.as_byte()))
                        .unwrap_or_default(),
                ));
                if let Some(endpoint) = entry.ipv6() {
                    facts.ipv6_sources.push(endpoint.to_string());
                }
            }
        }
    }
    Ok(facts)
}
