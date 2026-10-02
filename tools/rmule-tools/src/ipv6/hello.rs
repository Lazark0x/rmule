//! `rmule-tools ipv6 hello` — dial one peer in whichever family its endpoint
//! names, advertise the IPv6 dialect's hello block, and write down what the
//! counterparty's own `OP_HELLOANSWER` carried.
//!
//! The row is Stimulus; the evidence is the answer frame beside it, retained
//! byte-exact from the connection's capture so a flow can promote it as a
//! fixture with the body's own prefix. Three facts the flow judges come out of
//! the counterparty's tags rather than out of rmule's beliefs: its **Static
//! Capability Claim** (`CT_MOD_MISCOPTIONS 0xAA`), its own reachable IPv6
//! (`CT_MOD_IP_V6 0xAE`), and whether it reflected *our* advertised address
//! back at us (`CT_MOD_YOUR_IP 0xAD`, hash form) — which is the round trip
//! ADR-0092's `ipv6-hello-tags` row asserts.

use std::net::Ipv6Addr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args;
use rmule_net::peer::{ConnectOptions as PeerConnectOptions, Connection as PeerConnection};
use rmule_peer::{PeerEvent, PeerHandshakeContext, UdpPortsAdvert};
use rmule_primitives::{ClientId, ClientIdentity, Ed2kText, PeerEndpoint, UserHash};

use crate::capture::{hex_lower, write_new};
use crate::driver_row::Row;
use crate::operand::{parse_peer_endpoint, parse_user_hash};

/// The peer protocol byte and the answer opcode the fixture is cut at.
const PEER_PROTOCOL: u8 = 0xE3;
const OP_HELLOANSWER: u8 = 0x4C;
/// `OP_EMULEINFO` under the eMule protocol byte.
const EMULE_PROTOCOL: u8 = 0xC5;
const OP_EMULEINFO: u8 = 0x01;

/// Old-format eD2k tag types, as the tolerant answer reader sizes them.
const TAGTYPE_HASH: u8 = 0x01;
const TAGTYPE_STRING: u8 = 0x02;
const TAGTYPE_UINT32: u8 = 0x03;
const TAGTYPE_FLOAT32: u8 = 0x04;
const TAGTYPE_BOOL: u8 = 0x05;
const TAGTYPE_BLOB: u8 = 0x07;
const TAGTYPE_UINT16: u8 = 0x08;
const TAGTYPE_UINT8: u8 = 0x09;
const TAGTYPE_STR1: u8 = 0x11;
const TAGTYPE_STR16: u8 = 0x20;

/// The dialect tag ids this reader promotes out of a hello answer.
const CT_MOD_MISCOPTIONS: u8 = 0xAA;
const CT_MOD_YOUR_IP: u8 = 0xAD;
const CT_MOD_IP_V6: u8 = 0xAE;

/// The `CT_MOD_MISCOPTIONS` bits ADR-0087 models.
const MODMISC_EXTSX: u32 = 1 << 0;
const MODMISC_IPV6: u32 = 1 << 2;
const MODMISC_EXTSX_SKIPTAGS: u32 = 1 << 5;

#[derive(Debug, Args)]
pub(crate) struct Ipv6HelloArgs {
    /// The peer to dial, `a.b.c.d:port` or `[addr]:port`. The literal's family
    /// is the family dialled — there is no probing here, because the flow is
    /// measuring what happens *in* a family it chose.
    #[arg(long)]
    peer: String,
    /// Our Known IPv6 for this hello's `CT_MOD_IP_V6` tag. Omitted, the tag is
    /// omitted — which is the honest advert for a node holding no v6, and the
    /// control leg for a flow that wants to see the difference.
    #[arg(long)]
    advertise_ipv6: Option<Ipv6Addr>,
    /// The address the counterparty is expected to name as its own. Recorded
    /// as a comparison, never enforced: a body that named a different one has
    /// told us something, and a driver that failed here would throw it away.
    #[arg(long)]
    expect_peer_ipv6: Option<Ipv6Addr>,
    /// Local nickname tag.
    #[arg(long, default_value = "rmule-tools")]
    nickname: String,
    /// Our 16-byte user hash as hex (32 chars).
    #[arg(long, default_value = "42424242424242424242424242424242")]
    user_hash: String,
    /// The TCP port the hello advertises.
    #[arg(long, default_value_t = 4662)]
    tcp_port: u16,
    /// `CT_VERSION`.
    #[arg(long, default_value_t = 60)]
    protocol_version: u32,
    /// The Client ID the hello carries. **Zero by default**, which is what a
    /// client with no server session sends and what aMule itself sends in the
    /// same position; a High-ID literal that no address backs is refused
    /// outright by kno's aMule on a native IPv6 accept, which measures the
    /// fabrication rather than the dialect. A value under `0x01000000` makes
    /// this side present as firewalled.
    #[arg(long, default_value_t = 0)]
    client_id: u32,
    /// Directory for the connection's capture artifacts.
    #[arg(long)]
    capture: PathBuf,
    /// Where to write the row.
    #[arg(long)]
    out: PathBuf,
    /// Advertise these real client-UDP and Kad UDP ports (`CT_EMULE_UDPPORTS`),
    /// as `client:kad`. A counterparty attributes a later reask datagram to the
    /// client it holds by *that* port, so the `ipv6-udp-key` row needs the
    /// hello to name the port its datagram will actually leave from — otherwise
    /// the reask arrives from an unknown sender and is answered in the clear.
    #[arg(long)]
    advertise_udp_ports: Option<String>,
    /// Advertise protocol obfuscation on this hello (ADR-0042), so the
    /// counterparty's `shouldReceiveCryptUDPPackets()` gate opens and it keys
    /// its UDP replies to us.
    #[arg(long)]
    crypt: bool,
    /// Hold the established link open this long before closing. kno's aMule
    /// only classifies its own IPv6 on the accept path, and a link torn down
    /// in the same instant is reaped before it is logged.
    #[arg(long, default_value_t = 4)]
    hold_secs: u64,
    /// TCP connect budget, seconds.
    #[arg(long, default_value_t = 10)]
    connect_timeout: u64,
    /// Hello-answer budget, seconds.
    #[arg(long, default_value_t = 20)]
    response_timeout: u64,
}

/// What one dial learned about the counterparty.
#[derive(Debug, Default)]
struct HelloFacts {
    connected: bool,
    identified: bool,
    failure: String,
    peer_user_hash: String,
    peer_client_id: u32,
    peer_nickname: String,
    mod_misc_present: bool,
    mod_misc_word: u32,
    mod_misc_bits: Vec<String>,
    claims_extsx: bool,
    claims_ipv6: bool,
    claims_extsx_skiptags: bool,
    peer_ipv6: String,
    peer_ipv6_as_expected: bool,
    reflected_ipv6: String,
    reflection_matches_advert: bool,
    serving_buddy_ipv6: String,
    unknown_tag_ids: Vec<String>,
    hello_answer_bytes: usize,
    hello_answer_file: String,
    hello_answer_prefix: String,
    /// The tag count the answer's own header declared, and how many whole tags
    /// its tag block actually carried. They differ when a counterparty counts a
    /// tag it then does not write — which every reader sees as a malformed
    /// block, so the two numbers are recorded rather than reconciled.
    answer_tags_declared: i64,
    answer_tags_read: i64,
    answer_tag_block_consistent: bool,
    /// The Client Software rmule's session read off the answer — and off an
    /// `OP_EMULEINFO` the counterparty sent, when it sent one.
    peer_software: String,
    /// The counterparty sent `OP_EMULEINFO`: it read rmule's hello as a
    /// pre-0.42 one, which no modern mule should.
    peer_sent_emule_info: bool,
    /// The counterparty hung up while the link was held: its reaction to the
    /// hello it was sent, if it objected to it.
    peer_closed_during_hold: bool,
    /// What else the session reported while the link was held.
    events_during_hold: Vec<String>,
}

const fn family(peer: PeerEndpoint) -> &'static str {
    match peer {
        PeerEndpoint::V4(_) => "v4",
        PeerEndpoint::V6(_) => "v6",
    }
}

/// Dial the peer, read its hello answer, and write the row.
///
/// # Errors
/// If the endpoint or hash cannot be parsed, or the row cannot be written. A
/// peer that refuses the connection or never answers is **not** an error: that
/// is a row with `connected`/`identified` false and the reason in `failure`,
/// which is the measurement a flow has to be able to record.
pub(crate) async fn run_hello(args: Ipv6HelloArgs) -> Result<()> {
    let peer = parse_peer_endpoint(&args.peer)?;
    let user_hash = UserHash::from_bytes(parse_user_hash(&args.user_hash)?);
    let identity = ClientIdentity::new(
        user_hash,
        Ed2kText::from_utf8(&args.nickname),
        args.tcp_port,
        args.protocol_version,
    );
    let ctx = PeerHandshakeContext {
        identity,
        client_id: ClientId::from_u32(args.client_id),
        connected_server: None,
    };
    let udp_ports = args
        .advertise_udp_ports
        .as_deref()
        .map(parse_udp_ports)
        .transpose()?;
    let options = PeerConnectOptions {
        capture_dir: Some(args.capture.clone()),
        connect_timeout: Duration::from_secs(args.connect_timeout),
        hello_timeout: Duration::from_secs(args.response_timeout),
        ipv6: args.advertise_ipv6,
        udp_ports,
        obfuscation: args.crypt.then_some(rmule_net::peer::ObfuscationConfig {
            policy: rmule_net::peer::ObfuscationPolicy::Supported,
        }),
        ..Default::default()
    };

    let mut facts = HelloFacts::default();
    match PeerConnection::connect(peer, ctx, options).await {
        Ok(connection) => {
            facts.connected = true;
            converse(connection, &args, &mut facts).await;
            // The tolerant read runs whether or not the strict session reader
            // accepted the answer: a frame the session refused is still the
            // counterparty's own bytes, and refusing to look at them would
            // turn a measurable defect into an unexplained silence.
            attach_hello_answer(&mut facts, &args)?;
        }
        Err(error) => facts.failure = error.to_string(),
    }

    println!(
        "ipv6-hello peer={peer} family={} identified={} claims_ipv6={} peer_ipv6={}",
        family(peer),
        facts.identified,
        facts.claims_ipv6,
        facts.peer_ipv6
    );
    let mut row = Row::new(
        "rmule-tools ipv6 hello — the counterparty's own OP_HELLOANSWER, read\n\
         through rmule's dialect reader (ADR-0087). Stimulus about rmule; the\n\
         retained answer frame beside it is the evidence.",
    );
    row.str("peer", &peer.to_string())
        .str("dialed_family", family(peer))
        .str(
            "advertised_ipv6",
            &args
                .advertise_ipv6
                .map(|a| a.to_string())
                .unwrap_or_default(),
        )
        .bool("connected", facts.connected)
        .bool("identified", facts.identified)
        .str("failure", &facts.failure)
        .str("peer_user_hash", &facts.peer_user_hash)
        .int("peer_client_id", i64::from(facts.peer_client_id))
        .str("peer_nickname", &facts.peer_nickname)
        .bool("mod_misc_present", facts.mod_misc_present)
        .int("mod_misc_word", i64::from(facts.mod_misc_word))
        .list("mod_misc_bits", &facts.mod_misc_bits)
        .bool("claims_extsx", facts.claims_extsx)
        .bool("claims_ipv6", facts.claims_ipv6)
        .bool("claims_extsx_skiptags", facts.claims_extsx_skiptags)
        .str("peer_ipv6", &facts.peer_ipv6)
        .bool("peer_ipv6_as_expected", facts.peer_ipv6_as_expected)
        .str("reflected_ipv6", &facts.reflected_ipv6)
        .bool("reflection_matches_advert", facts.reflection_matches_advert)
        .str("serving_buddy_ipv6", &facts.serving_buddy_ipv6)
        .list("unknown_tag_ids", &facts.unknown_tag_ids)
        .int(
            "hello_answer_bytes",
            i64::try_from(facts.hello_answer_bytes).unwrap_or(-1),
        )
        .str("hello_answer_file", &facts.hello_answer_file)
        .str("hello_answer_prefix", &facts.hello_answer_prefix)
        .int("answer_tags_declared", facts.answer_tags_declared)
        .int("answer_tags_read", facts.answer_tags_read)
        .bool(
            "answer_tag_block_consistent",
            facts.answer_tag_block_consistent,
        )
        .str("peer_software", &facts.peer_software)
        .bool("peer_sent_emule_info", facts.peer_sent_emule_info)
        .bool("peer_closed_during_hold", facts.peer_closed_during_hold)
        .list("events_during_hold", &facts.events_during_hold);
    crate::driver_row::write_row(&args.out, row)
}

/// Hold the established link until the peer identifies itself, then keep it
/// open for `--hold-secs` so the counterparty's own accept path can run.
async fn converse(mut connection: PeerConnection, args: &Ipv6HelloArgs, facts: &mut HelloFacts) {
    facts.failure = "the peer accepted TCP but never identified itself".to_owned();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(args.response_timeout);
    loop {
        let event = tokio::select! {
            () = tokio::time::sleep_until(deadline) => break,
            event = connection.next_event() => event,
        };
        match event {
            Some(PeerEvent::PeerIdentified { identity }) => {
                facts.identified = true;
                facts.failure = String::new();
                facts.peer_software = format!("{:?}", identity.software());
                facts.peer_user_hash = identity.user_hash().to_hex_upper();
                facts.peer_client_id = identity.client_id().as_u32();
                facts.peer_nickname = identity
                    .nickname()
                    .map(ToString::to_string)
                    .unwrap_or_default();
                if let Some(claim) = identity.mod_misc_options() {
                    facts.mod_misc_present = true;
                    facts.mod_misc_word = claim.bits();
                    facts.claims_extsx = claim.supports_ext_sx();
                    facts.claims_ipv6 = claim.supports_ipv6();
                    facts.claims_extsx_skiptags = claim.skips_unknown_ext_sx_tags();
                    for (set, name) in [
                        (facts.claims_extsx, "extsx"),
                        (facts.claims_ipv6, "ipv6"),
                        (facts.claims_extsx_skiptags, "extsx-skiptags"),
                    ] {
                        if set {
                            facts.mod_misc_bits.push(name.to_owned());
                        }
                    }
                }
                if let Some(address) = identity.peer_ipv6() {
                    facts.peer_ipv6 = address.to_string();
                    facts.peer_ipv6_as_expected = args.expect_peer_ipv6 == Some(address);
                }
                if let Some(address) = identity.reflected_ipv6() {
                    facts.reflected_ipv6 = address.to_string();
                    facts.reflection_matches_advert = args.advertise_ipv6 == Some(address);
                }
                if let Some(address) = identity.serving_buddy_ipv6() {
                    facts.serving_buddy_ipv6 = address.to_string();
                }
                facts.unknown_tag_ids = identity
                    .unknown_tags()
                    .iter()
                    .map(|tag| {
                        tag.name()
                            .id()
                            .map_or_else(|| "named".to_owned(), |id| format!("0x{id:02X}"))
                    })
                    .collect();
                break;
            }
            Some(PeerEvent::Disconnected { reason }) => {
                facts.failure = format!("{reason:?}");
                break;
            }
            Some(event) => println!("{event}"),
            None => break,
        }
    }

    let hold_until = tokio::time::Instant::now() + Duration::from_secs(args.hold_secs);
    while facts.identified {
        let event = tokio::select! {
            () = tokio::time::sleep_until(hold_until) => break,
            event = connection.next_event() => event,
        };
        match event {
            Some(PeerEvent::PeerSoftwareRevised { software }) => {
                facts.peer_software = format!("{software:?}");
                facts
                    .events_during_hold
                    .push("PeerSoftwareRevised".to_owned());
            }
            Some(PeerEvent::Disconnected { reason }) => {
                facts.peer_closed_during_hold = true;
                facts
                    .events_during_hold
                    .push(format!("Disconnected {reason:?}"));
                break;
            }
            Some(event) => facts.events_during_hold.push(event.to_string()),
            None => {
                facts.peer_closed_during_hold = true;
                break;
            }
        }
    }
    tokio::time::sleep_until(hold_until).await;
    let _ = connection.shutdown().await;
}

/// `client:kad` — the two real UDP ports the hello advertises.
fn parse_udp_ports(value: &str) -> Result<UdpPortsAdvert> {
    let (client, kad) = value
        .split_once(':')
        .with_context(|| format!("expected client:kad in --advertise-udp-ports {value}"))?;
    Ok(UdpPortsAdvert::new(
        client.parse().context("client UDP port")?,
        kad.parse().context("Kad UDP port")?,
    ))
}

/// Cut the counterparty's own `OP_HELLOANSWER` frame out of the capture and
/// retain it beside the row — the fixture candidate, byte-exact.
fn attach_hello_answer(facts: &mut HelloFacts, args: &Ipv6HelloArgs) -> Result<()> {
    let inbound = args.capture.join("inbound.bin");
    let Ok(stream) = std::fs::read(&inbound) else {
        return Ok(());
    };
    facts.peer_sent_emule_info =
        crate::ipv6::first_frame(&stream, EMULE_PROTOCOL, OP_EMULEINFO).is_some();
    let Some(frame) = crate::ipv6::first_frame(&stream, PEER_PROTOCOL, OP_HELLOANSWER) else {
        return Ok(());
    };
    let path = args.capture.join("helloanswer.bin");
    write_new(&path, frame)?;
    facts.hello_answer_bytes = frame.len();
    facts.hello_answer_file = path.display().to_string();
    facts.hello_answer_prefix = hex_lower(&frame[..frame.len().min(16)]);
    read_answer_tags(facts, frame, args);
    Ok(())
}

/// Walk the retained answer's tag block tolerantly and fill in whatever the
/// counterparty's own bytes carry.
///
/// The strict session reader is the one that decides whether a peer is usable,
/// and it is right to refuse a frame whose declared tag count overruns its tag
/// block. But the bytes are still evidence, and a flow that threw them away
/// could not say *what* the counterparty claimed while getting the count wrong.
/// So this walks what is there, stops at the first tag it cannot size, and
/// records the count it read beside the count that was declared.
fn read_answer_tags(facts: &mut HelloFacts, frame: &[u8], args: &Ipv6HelloArgs) {
    // `[proto][len u32][opcode]` then `userhash 16 | client id 4 | port 2 |
    // tag count 4`.
    let Some(body) = frame.get(6..) else { return };
    // The answer's own header, which is whole whatever its tag block does: a
    // counterparty that miscounts its tags still named itself correctly, and a
    // flow that could not read the user hash could not key the UDP leg.
    if facts.peer_user_hash.is_empty() {
        if let Some(hash) = body.get(..16) {
            facts.peer_user_hash = hex_lower(hash).to_uppercase();
        }
        if let Some(id) = body.get(16..20) {
            facts.peer_client_id = u32::from_le_bytes([id[0], id[1], id[2], id[3]]);
        }
    }
    let Some(count) = body.get(22..26) else {
        return;
    };
    facts.answer_tags_declared =
        i64::from(u32::from_le_bytes([count[0], count[1], count[2], count[3]]));
    let mut rest = &body[26..];
    let mut read = 0i64;
    while let Some((id, value, tail)) = next_tag(rest) {
        read += 1;
        rest = tail;
        match (id, &value) {
            (Some(CT_MOD_MISCOPTIONS), TagValue::Int(word)) => {
                facts.mod_misc_present = true;
                facts.mod_misc_word = *word;
                facts.claims_extsx = word & MODMISC_EXTSX != 0;
                facts.claims_ipv6 = word & MODMISC_IPV6 != 0;
                facts.claims_extsx_skiptags = word & MODMISC_EXTSX_SKIPTAGS != 0;
                for (set, name) in [
                    (facts.claims_extsx, "extsx"),
                    (facts.claims_ipv6, "ipv6"),
                    (facts.claims_extsx_skiptags, "extsx-skiptags"),
                ] {
                    if set && !facts.mod_misc_bits.iter().any(|bit| bit == name) {
                        facts.mod_misc_bits.push(name.to_owned());
                    }
                }
            }
            (Some(CT_MOD_IP_V6), TagValue::Hash(bytes)) if facts.peer_ipv6.is_empty() => {
                let address = Ipv6Addr::from(*bytes);
                facts.peer_ipv6 = address.to_string();
                facts.peer_ipv6_as_expected = args.expect_peer_ipv6 == Some(address);
            }
            (Some(CT_MOD_YOUR_IP), TagValue::Hash(bytes)) if facts.reflected_ipv6.is_empty() => {
                let address = Ipv6Addr::from(*bytes);
                facts.reflected_ipv6 = address.to_string();
                facts.reflection_matches_advert = args.advertise_ipv6 == Some(address);
            }
            _ => {}
        }
    }
    facts.answer_tags_read = read;
    // The block is consistent when the declared count was reached and nothing
    // but the 6-byte connected-server endpoint is left over.
    facts.answer_tag_block_consistent = read == facts.answer_tags_declared && rest.len() == 6;
}

/// The value forms this reader needs to tell apart.
enum TagValue {
    Int(u32),
    Hash([u8; 16]),
    Other,
}

/// Size one old-format eD2k tag off the front of `data`, returning its name id
/// (when it has a one-byte name), its value, and the rest.
fn next_tag(data: &[u8]) -> Option<(Option<u8>, TagValue, &[u8])> {
    let (&raw_type, rest) = data.split_first()?;
    let (kind, id, rest) = if raw_type & 0x80 != 0 {
        let (&id, rest) = rest.split_first()?;
        (raw_type & 0x7F, Some(id), rest)
    } else {
        let len = u16::from_le_bytes([*rest.first()?, *rest.get(1)?]) as usize;
        let name = rest.get(2..2 + len)?;
        let id = (len == 1).then(|| name[0]);
        (raw_type, id, rest.get(2 + len..)?)
    };
    let (value, rest) = match kind {
        TAGTYPE_HASH => {
            let bytes: [u8; 16] = rest.get(..16)?.try_into().ok()?;
            (TagValue::Hash(bytes), rest.get(16..)?)
        }
        TAGTYPE_STRING => {
            let len = u16::from_le_bytes([*rest.first()?, *rest.get(1)?]) as usize;
            (TagValue::Other, rest.get(2 + len..)?)
        }
        TAGTYPE_UINT32 | TAGTYPE_FLOAT32 => {
            let word = u32::from_le_bytes(rest.get(..4)?.try_into().ok()?);
            (TagValue::Int(word), rest.get(4..)?)
        }
        TAGTYPE_BOOL | TAGTYPE_UINT8 => (TagValue::Int(u32::from(*rest.first()?)), rest.get(1..)?),
        TAGTYPE_UINT16 => {
            let word = u16::from_le_bytes([*rest.first()?, *rest.get(1)?]);
            (TagValue::Int(u32::from(word)), rest.get(2..)?)
        }
        TAGTYPE_BLOB => {
            let len = u32::from_le_bytes(rest.get(..4)?.try_into().ok()?) as usize;
            (TagValue::Other, rest.get(4 + len..)?)
        }
        TAGTYPE_STR1..=TAGTYPE_STR16 => {
            let len = usize::from(kind - TAGTYPE_STR1 + 1);
            (TagValue::Other, rest.get(len..)?)
        }
        _ => return None,
    };
    Some((id, value, rest))
}
