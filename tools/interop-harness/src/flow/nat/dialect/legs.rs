//! What each IPv6-dialect flow actually drives, and the claims it draws from the
//! counterparty's answer.
//!
//! Every claim below reads a **driver row** — rmule's own account — only to
//! *locate* the counterparty's statement, and then judges that statement. The
//! row says "the peer's hello carried `CT_MOD_IP_V6` naming `3fff:ed2:1::2`";
//! the evidence is the retained `OP_HELLOANSWER` frame those bytes came from,
//! which the same leg writes into the run dir.
//!
//! One of the six cannot reach its ideal observable at the pins this repo
//! carries, and says so as claims rather than as silence: the server-half row
//! has no IPv6-capable `ed2ksrv` build to talk to.

use anyhow::Result;

use crate::flow::bench::Bench;
use crate::flow::nat::claims::measured_total;
use crate::flow::nat::dialect::bench::{
    HOST_AMULE_KNO, HOST_DRIVER, HOST_ED2KSRV, HOST_EMULEQT, HOST_LEGACY_AMULE, Ipv6DialectOptions,
    Stage, body_log, container_name, out, run_driver,
};
use crate::flow::nat::dialect::verdict::{Claim, DriverRow, Evidence};
use crate::flow::nat::dialect::{
    BODY_CLIENT_UDP_PORT, BODY_PEER_TCP_PORT, ED2KSRV_TCP_PORT, Ipv6Flow,
};

/// rmule's own user hash in every IPv6-dialect leg. Fixed so the counterparty's
/// obfuscated reply is keyed on a value the verdict can name.
pub(super) const RMULE_USER_HASH: &str = "42424242424242424242424242424242";

/// A Low-ID literal for the rung-0 row: under `0x01000000`, so the chooser
/// sees a firewalled peer on IPv4 whatever its IPv6 says.
const LOW_ID: u32 = 42;

/// Drive the flow and return its claims plus the standing note a reader needs.
///
/// # Errors
/// If a driver container cannot run or its row cannot be read.
pub(crate) fn drive(
    bench: &mut Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
) -> Result<(Vec<Claim>, String)> {
    match options.flow {
        Ipv6Flow::HelloTags => hello_tags(bench, options, stage),
        Ipv6Flow::ExtSx => super::ext_sx::drive(bench, options, stage),
        Ipv6Flow::ExtSxKno => super::ext_sx_kno::drive(bench, options, stage),
        Ipv6Flow::ExtSxEmit => super::ext_sx_emit::drive(bench, options, stage),
        Ipv6Flow::DownloadRung0 => super::download_rung0::drive(bench, options, stage),
        Ipv6Flow::ExtSxCore => super::ext_sx_core::drive(bench, options, stage),
        Ipv6Flow::DirectDialLowId => direct_dial(bench, options, stage),
        Ipv6Flow::KadTags => super::kad_tags::drive(bench, options, stage),
        Ipv6Flow::ServerSentinel => server_sentinel(bench, options, stage),
        Ipv6Flow::UdpKey => udp_key(bench, options, stage),
        Ipv6Flow::HelloSurface => super::hello_surface::drive(bench, options, stage),
    }
}

/// One `ipv6 hello` leg against a body, returning its row.
pub(super) fn hello_leg(
    bench: &Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
    leg: &str,
    peer: &str,
    expect_peer_ipv6: Option<&str>,
) -> Result<DriverRow> {
    hello_leg_with(bench, options, stage, leg, peer, expect_peer_ipv6, false)
}

/// The same leg, optionally advertising crypt and the real client-UDP port —
/// what a counterparty needs before it will key a UDP reply to us at all.
fn hello_leg_with(
    bench: &Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
    leg: &str,
    peer: &str,
    expect_peer_ipv6: Option<&str>,
    crypt_and_udp_ports: bool,
) -> Result<DriverRow> {
    let mut argv = vec![
        "ipv6".to_owned(),
        "hello".to_owned(),
        "--peer".to_owned(),
        peer.to_owned(),
        "--advertise-ipv6".to_owned(),
        stage.v6(HOST_DRIVER).to_owned(),
        "--user-hash".to_owned(),
        RMULE_USER_HASH.to_owned(),
        "--capture".to_owned(),
        out(&format!("{leg}-capture")),
        "--out".to_owned(),
        out(&format!("{leg}.toml")),
    ];
    if let Some(address) = expect_peer_ipv6 {
        argv.push("--expect-peer-ipv6".to_owned());
        argv.push(address.to_owned());
    }
    if crypt_and_udp_ports {
        argv.push("--crypt".to_owned());
        argv.push("--advertise-udp-ports".to_owned());
        argv.push(format!("{BODY_CLIENT_UDP_PORT}:0"));
    }
    run_driver(bench, options, stage, leg, &argv)?;
    DriverRow::read(&stage.leg_dir.join(format!("{leg}.toml")))
}

/// The claims one dialect-speaking body's own hello answer settles.
///
/// The first two are read off the *bytes*, through a tolerant walk of the
/// answer's tag block, so a counterparty whose declared tag count overruns its
/// own block still tells the flow what it claimed. The last two are the strict
/// reading — an answer a session can actually use — and they are replaced by an
/// **Exemption** when the block is inconsistent, because at that point the
/// counterparty's defect is the finding and asserting past it would only hide
/// it.
fn hello_claims(body: &str, row: &DriverRow, expected_v6: &str) -> Vec<Claim> {
    let mut claims = vec![
        Claim::about(
            format!("{body}-sent-a-hello-answer-over-ipv6"),
            row.int("hello_answer_bytes") > 0,
            Evidence::Captured,
            format!(
                "dialled {}; OP_HELLOANSWER {} bytes, prefix {}",
                row.text("peer"),
                row.int("hello_answer_bytes"),
                row.text("hello_answer_prefix")
            ),
        ),
        Claim::about(
            format!("{body}-claims-0xaa-ipv6"),
            row.flag("mod_misc_present") && row.flag("claims_ipv6"),
            Evidence::Captured,
            format!(
                "CT_MOD_MISCOPTIONS word 0x{:04X} in its own answer",
                row.int("mod_misc_word")
            ),
        ),
    ];
    if row.flag("answer_tag_block_consistent") {
        claims.push(Claim::about(
            format!("{body}-names-its-own-ipv6"),
            row.flag("peer_ipv6_as_expected"),
            Evidence::Captured,
            format!(
                "CT_MOD_IP_V6 = {:?}, expected {expected_v6}",
                row.text("peer_ipv6")
            ),
        ));
        claims.push(Claim::about(
            format!("{body}-answer-is-usable-by-a-strict-reader"),
            row.flag("identified"),
            Evidence::Captured,
            format!(
                "{} tags declared, {} read; rmule's session reader accepted it: {}",
                row.int("answer_tags_declared"),
                row.int("answer_tags_read"),
                row.flag("identified")
            ),
        ));
    } else {
        // An Exemption for one measured defect, so it holds only on that
        // defect's own signature: more tags declared than carried. Any other
        // inconsistency is not the defect the note documents.
        let declared = row.int("answer_tags_declared");
        let read = row.int("answer_tags_read");
        claims.push(Claim::about(
            format!("{body}-counts-a-tag-it-does-not-write"),
            read >= 0 && declared > read,
            Evidence::DocumentedAbsence,
            format!(
                "Exemption, and an upstream defect this run measured: {body}'s \
                 OP_HELLOANSWER declared {} tags and carried {}, leaving the trailing \
                 6-byte connected-server endpoint where the reader expects one more tag. \
                 The mechanism is in the fork's own source — SendHelloTypePacket() \
                 increments tagcount for CT_MOD_IP_V6 under `emitModIPv6` and then writes \
                 the tag with CTag::WriteTagToFile(data), whose `restrictive` parameter \
                 defaults to true and silently refuses any tag that is not str/int/float/\
                 blob (Tag.cpp:393). A TAGTYPE_HASH16 tag is therefore counted and never \
                 written. Every strict reader, aMule's own included, sees a malformed tag \
                 block; rmule refused it as ProtocolViolation and kept the bytes. The \
                 claim the answer *does* settle — the 0xAA word above — is asserted \
                 instead, and emule-qt is the oracle for the tag itself.",
                declared, read,
            ),
        ));
    }
    claims
}

/// `ipv6-hello-tags`: the `0xAA` claim and the `CT_MOD_IP_V6` round trip on two
/// independent oracles, plus the legacy-safety leg.
fn hello_tags(
    bench: &mut Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
) -> Result<(Vec<Claim>, String)> {
    let kno_v6 = stage.v6(HOST_AMULE_KNO).to_owned();
    let kno = hello_leg(
        bench,
        options,
        stage,
        "hello-amule-kno",
        &format!("[{kno_v6}]:{BODY_PEER_TCP_PORT}"),
        Some(&kno_v6),
    )?;
    let qt_v6 = stage.v6(HOST_EMULEQT).to_owned();
    let qt = hello_leg(
        bench,
        options,
        stage,
        "hello-emuleqt",
        &format!("[{qt_v6}]:{BODY_PEER_TCP_PORT}"),
        Some(&qt_v6),
    )?;
    // The legacy leg is dialled over IPv4 — stock aMule 2.3.3 binds no IPv6 —
    // and carries the *same* dialect hello block. What is being asserted is the
    // absence of the three legacy hazards below, so the tags have to actually
    // be there.
    let legacy = hello_leg(
        bench,
        options,
        stage,
        "hello-amule-legacy",
        &format!("{}:{BODY_PEER_TCP_PORT}", stage.v4(HOST_LEGACY_AMULE)),
        None,
    )?;

    let mut claims = hello_claims("amule-kno", &kno, &kno_v6);
    claims.extend(hello_claims("emuleqt", &qt, &qt_v6));
    claims.extend([
        // Legacy hazard 1 — an unknown TAG *type* makes aMule drop the packet.
        // `CT_MOD_IP_V6` rides `TAGTYPE_HASH`, which 2.3.3 knows, so the packet
        // must survive: the proof is that it answered at all.
        Claim::about(
            "legacy-answered-the-dialect-hello",
            legacy.flag("identified"),
            Evidence::Captured,
            format!(
                "stock aMule 2.3.3 answered a hello carrying 0xAA + 0xAE: identified={} \
                 failure={:?}",
                legacy.flag("identified"),
                legacy.text("failure")
            ),
        ),
        // Legacy hazard 3 — a 4-byte hello suffix mislabels the peer. aMule read
        // the body it was sent, so its answer names its own port and hash; a
        // shifted read would have produced neither.
        Claim::about(
            "legacy-read-the-hello-body-in-frame",
            !legacy.text("peer_user_hash").is_empty() && legacy.flag("answer_tag_block_consistent"),
            Evidence::Captured,
            format!(
                "aMule's answer named user hash {} and carried {} of {} declared tags with \
                 the connected-server endpoint exactly where a whole body puts it — a hello \
                 read four bytes out of alignment could produce neither. Its client id is \
                 {}, which is what a client with no server session sends.",
                legacy.text("peer_user_hash"),
                legacy.int("answer_tags_read"),
                legacy.int("answer_tags_declared"),
                legacy.int("peer_client_id")
            ),
        ),
        // The legacy body must ignore the dialect, not mirror it: a 2.3.3 that
        // came back with a `0xAA` word would mean the tag is not new after all.
        Claim::about(
            "legacy-ignored-the-dialect-tags",
            !legacy.flag("mod_misc_present") && legacy.text("peer_ipv6").is_empty(),
            Evidence::Captured,
            format!(
                "aMule's own answer carried mod_misc={} peer_ipv6={:?}",
                legacy.flag("mod_misc_present"),
                legacy.text("peer_ipv6")
            ),
        ),
        // Legacy hazard 2 — a new TCP protocol byte disconnects a legacy peer.
        // rmule emits none: every frame above rode `0xE3`, and the session held.
        Claim::about(
            "legacy-session-held-on-0xe3",
            legacy.flag("connected") && legacy.text("failure").is_empty(),
            Evidence::Captured,
            "the dialect adds tags under the existing 0xE3 protocol byte and no new one".to_owned(),
        ),
    ]);

    Ok((claims, String::new()))
}

/// `ipv6-udp-key`: the 35-byte client-UDP key, both ways.
///
/// **Plan correction.** ADR-0092 names `amule-kno` for this row, and kno's fork
/// cannot serve it: `ClientUDPSocket.cpp` leaves a datagram from a native IPv6
/// peer unmodified and says why — "the ed2k UDP obfuscation key is MD5 over our
/// user hash, a 32-bit address and a magic byte, and the protocol defines no
/// IPv6 input to it, so an obfuscated datagram from a native IPv6 peer is
/// undecryptable by any implementation". emule-qt, the dialect's own author,
/// implements the 35-byte form outright, so the row's oracle is emule-qt and
/// kno's refusal is measured beside it rather than assumed.
fn udp_key(
    bench: &mut Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
) -> Result<(Vec<Claim>, String)> {
    let qt_v6 = stage.v6(HOST_EMULEQT).to_owned();
    let qt_hello = hello_leg_with(
        bench,
        options,
        stage,
        "udpkey-hello-emuleqt",
        &format!("[{qt_v6}]:{BODY_PEER_TCP_PORT}"),
        Some(&qt_v6),
        true,
    )?;
    let qt_hash = qt_hello.text("peer_user_hash");
    let mut claims = vec![Claim::about(
        "emuleqt-hello-yielded-its-user-hash",
        !qt_hash.is_empty(),
        Evidence::Captured,
        format!("emule-qt's own hello named user hash {qt_hash:?}"),
    )];

    if !qt_hash.is_empty() {
        run_driver(
            bench,
            options,
            stage,
            "udpkey-emuleqt",
            &[
                "ipv6".to_owned(),
                "udp-key".to_owned(),
                "--peer".to_owned(),
                format!("[{qt_v6}]:{BODY_CLIENT_UDP_PORT}"),
                "--peer-user-hash".to_owned(),
                qt_hash.clone(),
                "--user-hash".to_owned(),
                RMULE_USER_HASH.to_owned(),
                "--our-address".to_owned(),
                stage.v6(HOST_DRIVER).to_owned(),
                "--bind-port".to_owned(),
                BODY_CLIENT_UDP_PORT.to_string(),
                "--capture".to_owned(),
                out("udpkey-emuleqt-capture"),
                "--out".to_owned(),
                out("udpkey-emuleqt.toml"),
            ],
        )?;
        let row = DriverRow::read(&stage.leg_dir.join("udpkey-emuleqt.toml"))?;
        claims.extend([
            Claim::about(
                "key-material-is-35-bytes-both-ways",
                row.int("outbound_key_material_bytes") == 35
                    && row.int("inbound_key_material_bytes") == 35,
                Evidence::RmuleOnly,
                format!(
                    "outbound {} bytes, inbound {} bytes (IPv4 would be 23)",
                    row.int("outbound_key_material_bytes"),
                    row.int("inbound_key_material_bytes")
                ),
            ),
            Claim::about(
                "emuleqt-parsed-our-35-byte-keyed-v6-datagram",
                row.flag("obfuscated_reply_received"),
                Evidence::Captured,
                format!(
                    "it answered an obfuscated OP_REASKFILEPING that carried no plaintext \
                     protocol byte, so it derived the key from our IPv6 source address at \
                     the 35-byte layout and no other: reply received={} plaintext={} raw={}",
                    row.flag("obfuscated_reply_received"),
                    row.flag("obfuscated_reply_was_plaintext"),
                    row.text("obfuscated_reply_raw")
                ),
            ),
            if row.flag("obfuscated_reply_was_plaintext") {
                Claim::absence(
                    "the-answer-to-an-unattributed-reask-comes-back-in-the-clear",
                    // The keyed reply is the thing absent: a plaintext answer
                    // that also decrypted would contradict the Exemption.
                    i64::from(row.flag("obfuscated_reply_decrypted")),
                    format!(
                        "Exemption: emule-qt keys a client-UDP reply only to a client it \
                         holds — UploadQueue.cpp's file-not-found branch calls \
                         sendPacket(..., sender->shouldReceiveCryptUDPPackets(), \
                         sender->userHash(), ...) when it has a sender and \
                         sendPacket(..., false, nullptr, ...) when it does not. Our reask \
                         named a hash it does not share, which is exactly the branch that \
                         answers before any sender lookup, so the reply arrived plaintext: \
                         {}. The outbound half of the 35-byte key is proven regardless — \
                         the counterparty could not have read our datagram with any other \
                         derivation.",
                        row.text("obfuscated_reply_raw")
                    ),
                )
            } else {
                Claim::about(
                    "reply-decrypted-with-the-35-byte-key",
                    row.flag("obfuscated_reply_decrypted"),
                    Evidence::Captured,
                    format!(
                        "recovered payload {:?}",
                        row.text("obfuscated_reply_payload")
                    ),
                )
            },
            Claim::about(
                "reply-is-op-filenotfound",
                row.int("obfuscated_reply_opcode") == 0x92,
                Evidence::Captured,
                format!(
                    "recovered opcode 0x{:02X}",
                    row.int("obfuscated_reply_opcode").max(0)
                ),
            ),
            Claim::about(
                "plaintext-control-answered",
                row.flag("plaintext_control_answered"),
                Evidence::Captured,
                "the control tells a silent crypt leg from a silent socket".to_owned(),
            ),
        ]);
    }

    // kno's own refusal, measured rather than read.
    let kno_v6 = stage.v6(HOST_AMULE_KNO).to_owned();
    let kno_hello = hello_leg_with(
        bench,
        options,
        stage,
        "udpkey-hello-amule-kno",
        &format!("[{kno_v6}]:{BODY_PEER_TCP_PORT}"),
        Some(&kno_v6),
        true,
    )?;
    let kno_hash = kno_hello.text("peer_user_hash");
    if !kno_hash.is_empty() {
        run_driver(
            bench,
            options,
            stage,
            "udpkey-amule-kno",
            &[
                "ipv6".to_owned(),
                "udp-key".to_owned(),
                "--peer".to_owned(),
                format!("[{kno_v6}]:{BODY_CLIENT_UDP_PORT}"),
                "--peer-user-hash".to_owned(),
                kno_hash,
                "--user-hash".to_owned(),
                RMULE_USER_HASH.to_owned(),
                "--our-address".to_owned(),
                stage.v6(HOST_DRIVER).to_owned(),
                "--bind-port".to_owned(),
                BODY_CLIENT_UDP_PORT.to_string(),
                "--capture".to_owned(),
                out("udpkey-amule-kno-capture"),
                "--out".to_owned(),
                out("udpkey-amule-kno.toml"),
            ],
        )?;
        let row = DriverRow::read(&stage.leg_dir.join("udpkey-amule-kno.toml"))?;
        // An answer to the obfuscated ask is kno having read it. The silence
        // is a measurement only beside a plaintext control that was answered:
        // without it a dead socket would read as the refusal.
        let obfuscated_answers = if row.flag("plaintext_control_answered") {
            i64::from(row.flag("obfuscated_reply_received"))
        } else {
            -1
        };
        claims.push(Claim::absence(
            "amule-kno-does-not-decrypt-a-native-v6-datagram",
            obfuscated_answers,
            format!(
                "kno's ClientUDPSocket.cpp passes an obfuscated datagram from a native IPv6 \
                 peer through undecrypted by design; measured here: obfuscated reply \
                 received={}, plaintext control answered={}",
                row.flag("obfuscated_reply_received"),
                row.flag("plaintext_control_answered")
            ),
        ));
    }

    Ok((
        claims,
        "ADR-0092 names amule-kno for this row; kno's fork implements no IPv6 input to the \
         ed2k UDP key and says so in its own source, so the oracle is emule-qt 73fff714 and \
         kno's refusal is recorded beside it."
            .to_owned(),
    ))
}

/// `ipv6-direct-dial-lowid`: two separate facts. The route tree picks rung 0
/// over every callback (`ipv6 route`, which decides and does not dial), and a
/// Low-ID hello dialled at the peer's IPv6 half lands (`ipv6 hello`, a
/// separate driver process). No routed Core dials here; `ipv6-download-rung0`
/// (`ipv6-download-rung0`) is the row where one download both chooses rung 0 and dials it.
fn direct_dial(
    bench: &mut Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
) -> Result<(Vec<Claim>, String)> {
    let kno_v6 = stage.v6(HOST_AMULE_KNO).to_owned();
    let peer_tcp = format!("{}:{BODY_PEER_TCP_PORT}", stage.v4(HOST_AMULE_KNO));

    run_driver(
        bench,
        options,
        stage,
        "route-rung-zero",
        &[
            "ipv6".to_owned(),
            "route".to_owned(),
            "--peer-client-id".to_owned(),
            LOW_ID.to_string(),
            "--peer-tcp".to_owned(),
            peer_tcp.clone(),
            "--peer-ipv6".to_owned(),
            kno_v6.clone(),
            "--external-v6".to_owned(),
            stage.v6(HOST_DRIVER).to_owned(),
            "--out".to_owned(),
            out("route-rung-zero.toml"),
        ],
    )?;
    let rung = DriverRow::read(&stage.leg_dir.join("route-rung-zero.toml"))?;

    run_driver(
        bench,
        options,
        stage,
        "route-control",
        &[
            "ipv6".to_owned(),
            "route".to_owned(),
            "--peer-client-id".to_owned(),
            LOW_ID.to_string(),
            "--peer-tcp".to_owned(),
            peer_tcp,
            "--peer-ipv6".to_owned(),
            kno_v6.clone(),
            "--families".to_owned(),
            "v4".to_owned(),
            "--out".to_owned(),
            out("route-control.toml"),
        ],
    )?;
    let control = DriverRow::read(&stage.leg_dir.join("route-control.toml"))?;

    // The dial itself, presented as the firewalled client the row is about.
    run_driver(
        bench,
        options,
        stage,
        "dial-lowid",
        &[
            "ipv6".to_owned(),
            "hello".to_owned(),
            "--peer".to_owned(),
            format!("[{kno_v6}]:{BODY_PEER_TCP_PORT}"),
            "--advertise-ipv6".to_owned(),
            stage.v6(HOST_DRIVER).to_owned(),
            "--expect-peer-ipv6".to_owned(),
            kno_v6.clone(),
            "--client-id".to_owned(),
            LOW_ID.to_string(),
            "--user-hash".to_owned(),
            RMULE_USER_HASH.to_owned(),
            "--capture".to_owned(),
            out("dial-lowid-capture"),
            "--out".to_owned(),
            out("dial-lowid.toml"),
        ],
    )?;
    let dial = DriverRow::read(&stage.leg_dir.join("dial-lowid.toml"))?;
    let kno_container = container_name(options.layout, "v6kno")?;
    let log = body_log(bench, stage, &kno_container, "amule-kno-body")?;
    let inbound_line = log
        .lines()
        .find(|line| line.to_lowercase().contains("inbound ipv6 connection from"))
        .unwrap_or_default()
        .trim()
        .to_owned();

    let claims = vec![
        Claim::about(
            "rung-zero-outranks-every-callback",
            rung.text("route") == "direct" && rung.flag("rung_zero"),
            Evidence::RmuleOnly,
            format!(
                "route={:?} for a Low-ID peer on our own server, holding {:?}",
                rung.text("route"),
                rung.text("our_ipv6")
            ),
        ),
        Claim::about(
            "control-without-our-ipv6-falls-back-to-the-server-callback",
            control.text("route") == "server",
            Evidence::RmuleOnly,
            format!(
                "route={:?} with the same peer while this node binds IPv4 only, so it holds \
                 no address to dial an IPv6 peer from — the AND is deliberate, and the \
                 rung-0 leg above differs from this one in exactly that",
                control.text("route")
            ),
        ),
        Claim::about(
            "the-v6-dial-reached-the-low-id-peer",
            dial.int("hello_answer_bytes") > 0,
            Evidence::Captured,
            format!(
                "a separate `ipv6 hello` driver, not the Core whose route is judged above, \
                 dialled kno's IPv6 half as a Low-ID client, and kno answered with its own \
                 OP_HELLOANSWER ({} bytes, prefix {}) — no callback was brokered and none \
                 could have been, since nothing on this bench is a server. Its answer is \
                 the malformed one `ipv6-hello-tags` measures ({} tags declared, {} \
                 carried), so the strict session reader refused it. The route choice and \
                 this dial are two facts; `ipv6-download-rung0` is where one download does both.",
                dial.int("hello_answer_bytes"),
                dial.text("hello_answer_prefix"),
                dial.int("answer_tags_declared"),
                dial.int("answer_tags_read"),
            ),
        ),
        Claim::about(
            "the-counterparty-logged-the-inbound-ipv6-connection",
            !inbound_line.is_empty(),
            Evidence::Captured,
            if inbound_line.is_empty() {
                "kno's log named no inbound IPv6 connection".to_owned()
            } else {
                inbound_line
            },
        ),
    ];
    Ok((claims, String::new()))
}

/// `ipv6-server-sentinel`: a capable server emits a **Sentinel Source** to a
/// capable session — and the pinned `ed2ksrv` is not one.
fn server_sentinel(
    bench: &mut Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
) -> Result<(Vec<Claim>, String)> {
    if !stage.ed2ksrv_present {
        return Ok((
            vec![Claim::blocked(
                "an-ipv6-capable-ed2k-server-to-talk-to",
                format!(
                    "the ed2ksrv counterparty image is not built on this bench, so nothing \
                     was measured here. The pin itself is the standing blocker: {} has zero \
                     IPv6, read off ed2k-server's source and confirmed against the image's \
                     own config schema, and no upstream build with IPv6 exists yet to pin.",
                    crate::flow::ed2ksrv::pin_text(),
                ),
            )],
            "Documented Absence, naming the missing pin: no upstream build with IPv6 exists yet, so no \
             ed2k-server build exists that could emit a Sentinel Source to a capable \
             session. This run additionally had no ed2ksrv image built, so the silence was \
             not re-measured on the wire; the flow takes that measurement automatically as \
             soon as the image is present, and asserts the real row as soon as the image is \
             IPv6-capable."
                .to_owned(),
        ));
    }
    run_driver(
        bench,
        options,
        stage,
        "server-probe",
        &[
            "ipv6".to_owned(),
            "server-probe".to_owned(),
            "--server".to_owned(),
            format!("{}:{ED2KSRV_TCP_PORT}", stage.v4(HOST_ED2KSRV)),
            "--advertise-ipv6".to_owned(),
            stage.v6(HOST_DRIVER).to_owned(),
            "--file-hash".to_owned(),
            "31D6CFE0D16AE931B73C59D7E0C089C0".to_owned(),
            "--user-hash".to_owned(),
            RMULE_USER_HASH.to_owned(),
            "--capture".to_owned(),
            out("server-probe-capture"),
            "--out".to_owned(),
            out("server-probe.toml"),
        ],
    )?;
    let row = DriverRow::read(&stage.leg_dir.join("server-probe.toml"))?;
    let capable = row.flag("server_claims_ipv6");

    let mut claims = vec![Claim::about(
        "the-session-reached-the-server",
        row.flag("login_accepted"),
        Evidence::Captured,
        format!(
            "login accepted={} client id {} (high={})",
            row.flag("login_accepted"),
            row.int("client_id"),
            row.flag("high_id")
        ),
    )];

    if capable {
        // The pin gained IPv6: the row lifts itself and asserts the real thing.
        claims.extend([
            Claim::about(
                "server-claims-srvcap-ipv6",
                true,
                Evidence::Captured,
                format!("SRV_TCPFLG = 0x{:08X}", row.int("tcp_flags_bits")),
            ),
            Claim::about(
                "server-emitted-a-sentinel-source",
                row.int("sentinel_count") > 0 && !row.flag("sentinel_tail_malformed"),
                Evidence::Captured,
                format!(
                    "{} sentinel records, tail malformed={}",
                    row.int("sentinel_count"),
                    row.flag("sentinel_tail_malformed")
                ),
            ),
            Claim::about(
                "serverident-carried-the-ipv6-probe-verdict",
                row.flag("ipv6_status_present"),
                Evidence::Captured,
                format!("ST_IPV6_STATUS = 0x{:02X}", row.int("ipv6_status_bits")),
            ),
            Claim::about(
                "serverlist-carried-a-trailing-v6-block",
                row.int("server_list_v6_count") > 0,
                Evidence::SingleOracle,
                format!(
                    "{} IPv6 servers in the trailing block. ADR-0087 classifies this surface \
                     and OP_CALLBACKREQUESTED_IPV6 (0x26) as single-oracle: eNode-go is the \
                     only implementation known to emit them.",
                    row.int("server_list_v6_count")
                ),
            ),
        ]);
    } else {
        // Every IPv6 surface the session could have seen, counted; unmeasured
        // when no capability word arrived, since then "SRV_TCPFLG_IPV6 clear"
        // was never read at all.
        let ipv6_surfaces = if row.flag("tcp_flags_present") {
            measured_total([
                i64::from(row.flag("ipv6_status_present")),
                i64::from(!row.text("server_ipv6").is_empty()),
                row.int("sentinel_count"),
                row.int("server_list_v6_count"),
            ])
        } else {
            -1
        };
        claims.push(Claim::absence(
            "no-ipv6-capable-ed2ksrv-pin-exists",
            ipv6_surfaces,
            format!(
                "measured: the ed2k-server image ({}) answered the login with \
                 SRV_TCPFLG = 0x{:08X} — SRV_TCPFLG_IPV6 (0x4000) clear — sent no \
                 ST_IPV6_STATUS ({}), named no CT_MOD_SVR_IP_V6 ({:?}), returned {} sentinel \
                 records and a server list with {} IPv6 entries. No upstream build with IPv6 \
                 exists yet to pin; until one does, this row \
                 has no counterparty and the harness fabricates none.",
                crate::flow::ed2ksrv::ED2KSRV.body_pin(&bench.docker, options.ed2ksrv_image),
                row.int("tcp_flags_bits"),
                row.flag("ipv6_status_present"),
                row.text("server_ipv6"),
                row.int("sentinel_count"),
                row.int("server_list_v6_count"),
            ),
        ));
        claims.push(Claim::blocked(
            "a-sentinel-source-dialled-from-a-capable-session",
            "blocked: no pinnable ed2k-server build speaks the dialect, so no \
             server can emit the row this flow would dial. The flow lifts itself the moment \
             `server_claims_ipv6` reads true against a re-pinned image — no code change.",
        ));
        claims.push(Claim::blocked(
            "op-callbackrequested-ipv6-0x26-consumed-from-a-server",
            "single-oracle and undriven: ADR-0087 records eNode-go as the only implementation \
             that emits 0x26 or the OP_SERVERLIST v6 block, and the bench carries no eNode-go \
             pin.",
        ));
    }

    let note = if capable {
        String::new()
    } else {
        format!(
            "Documented Absence. The IPv6-dialect server row needs an `ed2ksrv` pin with IPv6, \
             and none exists yet: the pinned build is {}, which carries no IPv6 at all. The absence \
             above is measured from the server's own login and OP_SERVERIDENT bytes rather \
             than read off a release note, and the flow asserts the real row automatically \
             once a capable pin appears.",
            crate::flow::ed2ksrv::pin_text(),
        )
    };
    Ok((claims, note))
}

#[cfg(test)]
mod tests {
    use super::hello_claims;
    use crate::flow::nat::dialect::verdict::DriverRow;

    fn exemption(declared: i64, read: i64) -> &'static str {
        let row = DriverRow::parse(&format!(
            "answer_tag_block_consistent = false\n\
             answer_tags_declared = {declared}\nanswer_tags_read = {read}\n"
        ))
        .expect("a hand-built row parses");
        hello_claims("amule-kno", &row, "3fff::2")
            .into_iter()
            .find(|claim| claim.name == "amule-kno-counts-a-tag-it-does-not-write")
            .expect("an inconsistent block carries the Exemption")
            .outcome
    }

    /// The Exemption documents one defect — a tag counted and never written —
    /// so an inconsistent block without that signature is not covered by it.
    #[test]
    fn the_tag_count_exemption_holds_only_on_an_over_count() {
        assert_eq!(exemption(12, 11), "held");
        assert_eq!(exemption(11, 11), "absent");
        assert_eq!(exemption(10, 11), "absent");
        assert_eq!(exemption(-1, -1), "absent");
    }
}
