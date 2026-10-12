//! `ipv6-extsx-emit`: `ipv6-extsx` with the roles swapped — rmule writes the
//! ExtSX record and emule-qt `73fff714` is the reader whose admission is
//! scored.
//!
//! rmule serves a one-part **Synthetic File** from a real `Core`
//! (`rmule-tools ed2k serve start`, logged in to `ed2ksrv` for its High ID),
//! and a **queued requester** that reached it over IPv6 with client id `0`,
//! naming `3fff:ed2:1::7` in its hello, holds the one upload slot. emule-qt
//! downloads the file: it learns rmule from the server, and its first file
//! request to a source carries the SX ask (`sendFileRequest`,
//! `DownloadClient.cpp:221`, never-asked-before passes
//! `isSourceRequestAllowed`). rmule answers in ExtSX, because emule-qt claims
//! `EXTXS`, with the queued requester as an IPv6-only source under the Low-ID
//! placeholder `1`.
//!
//! What is evidence is emule-qt's own behaviour after reading it. Its reader
//! (`processAnswerSources2`, `UpDownClient.cpp:4368`, into
//! `PartFile::addClientSources`, `PartFile.cpp:2709`) takes the record's
//! `CT_MOD_IP_V6` (`:2804`), keeps a Low-ID record that has a usable IPv6
//! (`:2855`, `:2884`), builds the client under the record's id — `1` is also
//! the placeholder it uses itself (`kNoIPv4SourceId`, `DownloadQueue.h:42`;
//! `:2894`) — admits it through `checkAndAddSource` (`DownloadQueue.cpp:321`,
//! `:2913`) and then dials it over IPv6 (`tryToConnect`, `:2914`,
//! `UpDownClient.cpp:1624`). A packet from emule-qt
//! to `[3fff:ed2:1::7]:4662` on its own tap is that dial; nothing else on the
//! bench tells emule-qt the address.
//!
//! A second, **dual-stack** requester is queued behind the first: it
//! reaches rmule over IPv4 with its own address as a High ID and names its
//! IPv6 in the hello, so rmule's answer carries it as one record — the IPv4 id
//! with `CT_MOD_IP_V6` beside it, the record emule-qt's own writer makes for
//! such a client (`KnownFile.cpp:937`). The record is lifted from emule-qt's
//! tap (the link is plaintext: emule-qt dials rmule with `encrypted=0`).
//! emule-qt's reader keeps both halves on one client (`PartFile.cpp:2894-2900`)
//! but has no line that prints a source's IPv6 beside its IPv4: what it shows
//! is the family it dials, and for a High ID that is the IPv4 — the
//! constructor presets the connect address from the id
//! (`UpDownClient.cpp:88-89`), and the IPv6-first rule applies only to a
//! source with none (`:1623-1627`). So its `tryToConnect` line naming the IPv4
//! under the High ID, with its packets on the tap, is the admission evidence.
//!
//! A third requester is queued too, and it **says it holds no part**:
//! it claims rmule's own extended-requests v1, so its name ask carries an
//! all-zero status, while the first two claim v0 and carry none — their parts
//! are unknown, which rmule answers to anyone (aMule's "send it and hope",
//! ADR-0055 §Serving). emule-qt's own name ask to rmule carries *its* status
//! (a fresh download: nothing held), so rmule's needed-part filter must leave
//! the holds-nothing source out of the one `0x84` it writes, beside the
//! dual-stack record it keeps. rmule answers every pooled source to an asker
//! whose status it could not read, so the record's absence is the filter
//! reading emule-qt's status.
//!
//! Once emule-qt has its answer, a fourth requester is queued the same
//! way as the dual-stack one but names an IPv6 no bench network routes, and a
//! real rmule download reads the serving rmule's answer: its dial of that half
//! fails, and it dials the source's IPv4 next ([`ipv4_fallback`]).

use std::ffi::OsString;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::docker::RunContainer;
use crate::flow::bench::{Bench, run_checked};
use crate::flow::ed2ksrv::Ed2ksrvImage;
use crate::flow::evidence::count_pcap_rows;
use crate::flow::gate::wait_for_container_log;
use crate::flow::nat::dialect::bench::{
    HOST_DRIVER, HOST_ED2KSRV, HOST_EMULEQT, HOST_QUEUED, HOST_QUEUED_DUAL_STACK,
    Ipv6DialectOptions, Stage, body_log, container_name, out, start_detached_driver, wait_for_exit,
};
use crate::flow::nat::dialect::ext_sx::{QUEUED_USER_HASH, SLOT_MARKER};
use crate::flow::nat::dialect::legs::RMULE_USER_HASH;
use crate::flow::nat::dialect::verdict::{Body, Claim, DriverRow, Evidence};
use crate::flow::nat::dialect::{BODY_PEER_TCP_PORT, ED2KSRV_TCP_PORT};
use crate::flow::nat::synthetic::write_hashed;
use crate::flow::wire_filter::{OP_EMULEPROT, WireFilter, lift_ed2k_frames};

mod holds_nothing;
mod ipv4_fallback;

use holds_nothing::{
    holds_nothing_claims, holds_nothing_queued_claim, start_holds_nothing_requester,
};
use ipv4_fallback::fallback_claims;

/// One part: emule-qt's download needs no hash set before it asks.
const SHARED_BYTES: u64 = 1 << 20;

/// The serving rmule's container role.
const SERVE_ROLE: &str = "v6serve";

/// The serving rmule prints this once it is logged in and has offered the
/// file, which is what makes it a source the server can hand out.
const ANNOUNCED_MARKER: &str = "serve.files_announced";

/// The serving rmule's line for an answered source ask.
const SERVED_MARKER: &str = "serve.sources_served";

/// emule-qt's readiness once logged in to the server.
const EMULEQT_READY_MARKER: &str = "rmule-emuleqt-ready";

/// How long the queued requester holds its slot. It spans emule-qt's link add,
/// its server source ask, its dial to rmule and the dial that follows the
/// answer, so it is generous; its exit is also what the flow waits on before
/// counting that dial.
const HOLD_SECS: u64 = 150;

/// The dual-stack requester's user hash: distinct from the IPv6-only one's,
/// since rmule keys its sources by hello.
const DUAL_USER_HASH: &str = "5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d";

/// The dual-stack requester's container role.
const DUAL_ROLE: &str = "v6dual";

/// The two requesters whose parts must read *unknown* claim extended-requests
/// v0, so no name ask of theirs carries a status.
const UNKNOWN_PARTS: [&str; 2] = ["--extended-requests", "0"];

/// How long the serving rmule runs; the bench tears it down sooner.
const SERVE_SECS: u64 = 600;

/// emule-qt's IPC surface, per its image's entrypoint defaults.
const EMULEQT_CONFIG_DIR: &str = "/config";
const EMULEQT_IPC_PORT: &str = "4712";

/// Stand up the server, the serving rmule and emule-qt (logged in, no download
/// yet). Returns emule-qt's container, which the tap watches: the download is
/// added only after the tap is attached.
///
/// # Errors
/// If a body cannot start or never becomes ready.
pub(super) fn start(
    bench: &mut Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &mut Stage,
    suffix: &str,
    timeout: Duration,
) -> Result<String> {
    let dir = stage.leg_dir.join("shared");
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let shared = write_hashed(&dir, SHARED_BYTES)?;
    let server_v4 = stage.v4(HOST_ED2KSRV).to_owned();

    let server = format!("rmule-interop-v6srv-{suffix}");
    let ed2ksrv = Ed2ksrvImage::check(&bench.docker, options.ed2ksrv_image)?;
    bench.start_extra(
        &server,
        ed2ksrv
            .container()
            .detach()
            .name(&server)
            .network(&stage.network)
            .ip(&server_v4)
            // Pinned although the server speaks no IPv6: an unpinned body
            // takes the /64's first free address, which another body holds.
            .ip6(stage.v6(HOST_ED2KSRV))
            .cap_add("NET_ADMIN"),
        "run the ed2k-server both clients log in to",
    )?;

    let file_name = shared
        .path
        .file_name()
        .and_then(|name| name.to_str())
        .context("the shared file has a utf-8 name")?;
    let serve_args = [
        "ed2k",
        "serve",
        "start",
        "--file",
        &format!("/out/shared/{file_name}"),
        "--server",
        &format!("{server_v4}:{ED2KSRV_TCP_PORT}"),
        "--listen",
        &format!("0.0.0.0:{BODY_PEER_TCP_PORT}"),
        // One slot, which the queued requester takes: emule-qt then waits,
        // and neither ends the other's relationship with rmule.
        "--upload-slots",
        "1",
        "--own-ip",
        stage.v4(HOST_DRIVER),
        "--user-hash",
        RMULE_USER_HASH,
        "--max-seconds",
        &SERVE_SECS.to_string(),
    ]
    .map(str::to_owned);
    let (serve, announced) = start_detached_driver(
        bench,
        options,
        stage,
        SERVE_ROLE,
        HOST_DRIVER,
        &serve_args,
        ANNOUNCED_MARKER,
    )?;
    if !announced {
        body_log(bench, stage, &serve, "rmule-serve")?;
        anyhow::bail!("the serving rmule {serve} never announced its file to the server");
    }

    let name = format!("rmule-interop-v6qt-{suffix}");
    bench.start_extra(
        &name,
        RunContainer::new(options.emuleqt_image)
            .detach()
            .name(&name)
            .network(&stage.network)
            .ip(stage.v4(HOST_EMULEQT))
            .ip6(stage.v6(HOST_EMULEQT))
            .cap_add("NET_ADMIN")
            .env("EMULEQT_SCENARIO_MODE", "ed2k-server")
            .env("ED2K_SERVER_HOST", &server_v4)
            .env("ED2K_SERVER_PORT", ED2KSRV_TCP_PORT.to_string())
            .env("EMULEQT_CRYPT_SUPPORTED", "true")
            .env("EMULEQT_CRYPT_REQUESTED", "true"),
        "run emule-qt logged in to the server",
    )?;
    wait_for_container_log(&bench.docker, &name, EMULEQT_READY_MARKER, timeout)?;

    stage.bodies.extend([
        Body {
            name: "emuleqt".to_owned(),
            image: options.emuleqt_image.to_owned(),
            pin: "ModderMule/emule-qt 73fff714".to_owned(),
            address_v4: stage.v4(HOST_EMULEQT).to_owned(),
            address_v6: stage.v6(HOST_EMULEQT).to_owned(),
        },
        Body {
            name: "ed2ksrv".to_owned(),
            image: options.ed2ksrv_image.to_owned(),
            pin: ed2ksrv.pin(),
            address_v4: server_v4,
            address_v6: stage.v6(HOST_ED2KSRV).to_owned(),
        },
    ]);
    stage.shared = Some(shared);
    Ok(name)
}

/// Drive the flow and return its claims.
///
/// # Errors
/// If a driver cannot run, the link cannot be added, or a count fails.
pub(super) fn drive(
    bench: &mut Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
) -> Result<(Vec<Claim>, String)> {
    let shared = stage.shared.as_ref().context("rmule shares a file")?;
    let serve = container_name(options.layout, SERVE_ROLE)?;
    let qt = container_name(options.layout, "v6qt")?;
    let queued_v6 = stage.v6(HOST_QUEUED).to_owned();
    let qt_v4 = stage.v4(HOST_EMULEQT).to_owned();
    let qt_v6 = stage.v6(HOST_EMULEQT).to_owned();

    let hold = [
        "ipv6".to_owned(),
        "hold-slot".to_owned(),
        "--peer".to_owned(),
        format!("[{}]:{BODY_PEER_TCP_PORT}", stage.v6(HOST_DRIVER)),
        "--file".to_owned(),
        shared.link.clone(),
        "--advertise-ipv6".to_owned(),
        queued_v6.clone(),
        "--user-hash".to_owned(),
        QUEUED_USER_HASH.to_owned(),
        "--capture".to_owned(),
        out("extsx-queued-capture"),
        "--out".to_owned(),
        out("extsx-queued.toml"),
        "--hold-secs".to_owned(),
        HOLD_SECS.to_string(),
        UNKNOWN_PARTS[0].to_owned(),
        UNKNOWN_PARTS[1].to_owned(),
    ];
    let (queued_container, slot_open) = start_detached_driver(
        bench,
        options,
        stage,
        "v6queued",
        HOST_QUEUED,
        &hold,
        SLOT_MARKER,
    )?;
    let mut claims = Vec::new();
    if !slot_open {
        wait_for_exit(bench, &queued_container)?;
        let queued = DriverRow::read(&stage.leg_dir.join("extsx-queued.toml"))?;
        body_log(bench, stage, &queued_container, "extsx-queued-driver")?;
        body_log(bench, stage, &serve, "rmule-serve")?;
        claims.push(Claim::about(
            "a-queued-requester-named-its-ipv6-and-holds-a-slot-on-rmule",
            false,
            Evidence::RmuleOnly,
            format!(
                "rmule never granted or queued the requester at [{queued_v6}]: identified={} \
                 failure={:?}",
                queued.flag("identified"),
                queued.text("failure"),
            ),
        ));
        return Ok((claims, String::new()));
    }

    let (dual_container, dual_open) = start_dual_stack_requester(bench, options, stage)?;
    if !dual_open {
        for container in [&queued_container, &dual_container] {
            wait_for_exit(bench, container)?;
        }
        let dual = DriverRow::read(&stage.leg_dir.join("extsx-dual.toml"))?;
        body_log(bench, stage, &dual_container, "extsx-dual-driver")?;
        body_log(bench, stage, &serve, "rmule-serve")?;
        claims.push(Claim::about(
            "a-dual-stack-requester-holds-a-place-on-rmule-over-ipv4",
            false,
            Evidence::RmuleOnly,
            format!(
                "rmule never granted or queued the dual-stack requester at {}: identified={} \
                 failure={:?}",
                stage.v4(HOST_QUEUED_DUAL_STACK),
                dual.flag("identified"),
                dual.text("failure"),
            ),
        ));
        return Ok((claims, String::new()));
    }

    let (none_container, none_open) = start_holds_nothing_requester(bench, options, stage)?;
    if !none_open {
        for container in [&queued_container, &dual_container, &none_container] {
            wait_for_exit(bench, container)?;
        }
        let none = DriverRow::read(&stage.leg_dir.join("extsx-none.toml"))?;
        body_log(bench, stage, &none_container, "extsx-none-driver")?;
        body_log(bench, stage, &serve, "rmule-serve")?;
        claims.push(holds_nothing_queued_claim(stage, &none));
        return Ok((claims, String::new()));
    }

    // The download starts only now, with the tap attached and every source
    // already queued, so emule-qt's first ask of rmule is the one answered.
    run_checked(
        bench.docker.exec(
            qt.clone(),
            [
                "emulecored",
                "--config",
                EMULEQT_CONFIG_DIR,
                "--port",
                EMULEQT_IPC_PORT,
                "--add-link",
                &shared.link,
            ]
            .map(OsString::from),
        ),
        "add the download to emule-qt",
    )?;
    let served = wait_for_container_log(
        &bench.docker,
        &serve,
        SERVED_MARKER,
        Duration::from_secs(options.timeout_secs),
    )
    .is_ok();
    // The fallback leg runs while every requester still holds its
    // place, and after emule-qt's answer, which it leaves as measured.
    let fallback = fallback_claims(bench, options, stage)?;
    for container in [&queued_container, &dual_container, &none_container] {
        wait_for_exit(bench, container)?;
    }
    let queued = DriverRow::read(&stage.leg_dir.join("extsx-queued.toml"))?;
    let dual = DriverRow::read(&stage.leg_dir.join("extsx-dual.toml"))?;
    let none = DriverRow::read(&stage.leg_dir.join("extsx-none.toml"))?;
    body_log(bench, stage, &queued_container, "extsx-queued-driver")?;
    body_log(bench, stage, &dual_container, "extsx-dual-driver")?;
    body_log(bench, stage, &none_container, "extsx-none-driver")?;
    let serve_log = body_log(bench, stage, &serve, "rmule-serve")?;
    let qt_log = body_log(bench, stage, &qt, "emuleqt-body")?;

    let tap = format!("{}-wan", container_name(options.layout, "v6tap")?);
    let dial_filter = format!(
        "ip6 and src host {qt_v6} and dst host {queued_v6} and tcp dst port {BODY_PEER_TCP_PORT}"
    );
    let dialled = count_pcap_rows(&bench.docker, &tap, "/capture/tap-wan.pcap", &dial_filter)?;
    let served_line = first_line(&serve_log, SERVED_MARKER);
    let qt_lines: Vec<&str> = qt_log
        .lines()
        .filter(|line| line.contains(&queued_v6) || line.contains("Source rejected"))
        .take(4)
        .collect();

    claims.extend([
        Claim::about(
            "a-queued-requester-named-its-ipv6-and-holds-a-slot-on-rmule",
            !queued.text("slot").is_empty(),
            Evidence::RmuleOnly,
            format!(
                "the requester reached rmule over IPv6 with client id 0, advertised \
                 CT_MOD_IP_V6 [{queued_v6}], and rmule answered its OP_STARTUPLOADREQ with \
                 slot={:?}; failure={:?}",
                queued.text("slot"),
                queued.text("failure"),
            ),
        ),
        Claim::about(
            "rmule-answered-emuleqts-source-ask",
            served && served_line.contains(&qt_v4),
            Evidence::RmuleOnly,
            format!(
                "the serving rmule's own line: {served_line:?} — its ExtSX record for an \
                 IPv6-only source carries the Low-ID placeholder 1 and CT_MOD_IP_V6"
            ),
        ),
        Claim::about(
            "emuleqt-dialled-the-extsx-ipv6-source",
            dialled > 0,
            Evidence::Captured,
            format!(
                "{dialled} packet(s) from emule-qt [{qt_v6}] to [{queued_v6}]:\
                 {BODY_PEER_TCP_PORT} on its own tap (`{dial_filter}`): the record was admitted \
                 as a source and dialled over IPv6. emule-qt's own lines naming the address or \
                 a rejection: {qt_lines:?}"
            ),
        ),
    ]);
    let answer = lift_answer(bench, stage, &tap)?;
    claims.extend(dual_stack_claims(
        bench,
        stage,
        &tap,
        &dual,
        answer.as_deref(),
        &qt_log,
    )?);
    claims.extend(holds_nothing_claims(stage, &none, answer.as_deref())?);
    claims.extend(fallback);
    Ok((claims, String::new()))
}

/// Queue the dual-stack requester on rmule: over IPv4, its own address as a
/// High ID, its IPv6 named in the hello. Returns its container and whether
/// rmule granted or queued it.
fn start_dual_stack_requester(
    bench: &mut Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
) -> Result<(String, bool)> {
    let v4: std::net::Ipv4Addr = stage
        .v4(HOST_QUEUED_DUAL_STACK)
        .parse()
        .context("the dual-stack requester's IPv4")?;
    let hold = [
        "ipv6".to_owned(),
        "hold-slot".to_owned(),
        "--peer".to_owned(),
        format!("{}:{BODY_PEER_TCP_PORT}", stage.v4(HOST_DRIVER)),
        "--file".to_owned(),
        stage
            .shared
            .as_ref()
            .context("rmule shares a file")?
            .link
            .clone(),
        "--advertise-ipv6".to_owned(),
        stage.v6(HOST_QUEUED_DUAL_STACK).to_owned(),
        // A High ID is the address in wire order: the octets read as a
        // little-endian word.
        "--client-id".to_owned(),
        u32::from_le_bytes(v4.octets()).to_string(),
        "--user-hash".to_owned(),
        DUAL_USER_HASH.to_owned(),
        "--capture".to_owned(),
        out("extsx-dual-capture"),
        "--out".to_owned(),
        out("extsx-dual.toml"),
        "--hold-secs".to_owned(),
        HOLD_SECS.to_string(),
        UNKNOWN_PARTS[0].to_owned(),
        UNKNOWN_PARTS[1].to_owned(),
    ];
    start_detached_driver(
        bench,
        options,
        stage,
        DUAL_ROLE,
        HOST_QUEUED_DUAL_STACK,
        &hold,
        SLOT_MARKER,
    )
}

/// The dual-stack leg's claims: rmule queued the requester, wrote it as one
/// record with both addresses, and emule-qt admitted that record as a High-ID
/// source and dialled the family it prefers for one.
fn dual_stack_claims(
    bench: &Bench,
    stage: &Stage,
    tap: &str,
    dual: &DriverRow,
    answer: Option<&[u8]>,
    qt_log: &str,
) -> Result<Vec<Claim>> {
    let qt_v4 = stage.v4(HOST_EMULEQT);
    let dual_v4 = stage.v4(HOST_QUEUED_DUAL_STACK);
    let dual_v6 = stage.v6(HOST_QUEUED_DUAL_STACK);
    let v4: std::net::Ipv4Addr = dual_v4.parse().context("the dual-stack requester's IPv4")?;
    let v6: std::net::Ipv6Addr = dual_v6.parse().context("the dual-stack requester's IPv6")?;

    let record = answer.and_then(|frame| dual_stack_record(frame, v4, v6));

    let dial_v4 = format!(
        "ip and src host {qt_v4} and dst host {dual_v4} and tcp dst port {BODY_PEER_TCP_PORT}"
    );
    let dial_v6 = format!("ip6 and dst host {dual_v6} and tcp dst port {BODY_PEER_TCP_PORT}");
    let dialled_v4 = count_pcap_rows(&bench.docker, tap, "/capture/tap-wan.pcap", &dial_v4)?;
    let dialled_v6 = count_pcap_rows(&bench.docker, tap, "/capture/tap-wan.pcap", &dial_v6)?;
    let hybrid = u32::from_be_bytes(v4.octets());
    let dial_line = format!(
        "tryToConnect: DIRECT TCP to {dual_v4}:{BODY_PEER_TCP_PORT} (userIDHybrid=0x{hybrid:08x})"
    );
    let qt_line = first_line(qt_log, &dial_line);

    Ok(vec![
        Claim::about(
            "a-dual-stack-requester-holds-a-place-on-rmule-over-ipv4",
            !dual.text("slot").is_empty(),
            Evidence::RmuleOnly,
            format!(
                "the requester reached rmule over IPv4 from {dual_v4} with that address as its \
                 High ID, advertised CT_MOD_IP_V6 [{dual_v6}], and rmule answered its \
                 OP_STARTUPLOADREQ with slot={:?}; failure={:?}",
                dual.text("slot"),
                dual.text("failure"),
            ),
        ),
        Claim::about(
            "rmule-wrote-the-dual-stack-source-with-both-addresses",
            record.is_some(),
            Evidence::RmuleOnly,
            format!(
                "rmule's OP_ANSWERSOURCES2 to emule-qt on its tap ({} bytes, `extsx-answer.bin`): \
                 the record for {dual_v4}:{BODY_PEER_TCP_PORT} is {record:?} — the IPv4 id \
                 with CT_MOD_IP_V6 [{dual_v6}] beside it",
                answer.map_or(0, <[u8]>::len),
            ),
        ),
        Claim::about(
            "emuleqt-admitted-the-dual-stack-record-and-dialled-its-ipv4-half",
            dialled_v4 > 0 && !qt_line.is_empty(),
            Evidence::Captured,
            format!(
                "emule-qt's own line {qt_line:?} and {dialled_v4} packet(s) to \
                 {dual_v4}:{BODY_PEER_TCP_PORT} on its tap (`{dial_v4}`): the record was \
                 admitted as a High-ID source, and a High ID is dialled over IPv4 \
                 (UpDownClient.cpp:88-89, :1623-1627). {dialled_v6} packet(s) to its IPv6 \
                 half [{dual_v6}]:{BODY_PEER_TCP_PORT} (`{dial_v6}`)."
            ),
        ),
    ])
}

/// Lift rmule's `0x84` to emule-qt off emule-qt's tap and keep it beside the
/// verdict (`extsx-answer.bin`, the link's segments in `extsx-answer.pcap`).
/// The frame is read out of the reassembled link: rmule writes it behind
/// whatever else it had queued, in the same segment.
fn lift_answer(bench: &Bench, stage: &Stage, tap: &str) -> Result<Option<Vec<u8>>> {
    let rmule_v4 = stage.v4(HOST_DRIVER);
    let qt_v4 = stage.v4(HOST_EMULEQT);
    let answer = WireFilter::ed2k(
        format!("src host {rmule_v4} and tcp src port {BODY_PEER_TCP_PORT} and dst host {qt_v4}"),
        &[OP_EMULEPROT],
        0x84,
    );
    let answer = lift_ed2k_frames(
        &bench.docker,
        tap,
        "/capture/tap-wan.pcap",
        &answer,
        "extsx-answer.pcap",
    )?
    .into_iter()
    .next()
    .map(|frame| frame.bytes);
    if let Some(bytes) = &answer {
        let path = stage.leg_dir.join("extsx-answer.bin");
        std::fs::write(&path, bytes).with_context(|| format!("write {}", path.display()))?;
    }
    Ok(answer)
}

/// The bytes of the ExtSX record in `frame` that names `v4` as its client id,
/// when its tag list opens with `CT_MOD_IP_V6` = `v6` — rmule writes the IPv6
/// tag first when the source declares no server.
fn dual_stack_record(
    frame: &[u8],
    v4: std::net::Ipv4Addr,
    v6: std::net::Ipv6Addr,
) -> Option<String> {
    let mut head = v4.octets().to_vec();
    head.extend_from_slice(&BODY_PEER_TCP_PORT.to_le_bytes());
    let at = frame
        .windows(head.len())
        .position(|window| window == head)?;
    let tags = frame.get(at + head.len()..)?;
    let mut ipv6_tag = vec![0x81, 0xae];
    ipv6_tag.extend_from_slice(&v6.octets());
    let record = tags.get(1..1 + ipv6_tag.len())?;
    (record == ipv6_tag.as_slice()).then(|| {
        frame[at..at + head.len() + 1 + ipv6_tag.len()]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    })
}

fn first_line<'a>(log: &'a str, marker: &str) -> &'a str {
    log.lines()
        .find(|line| line.contains(marker))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::dual_stack_record;

    /// The record is found by its IPv4 id wherever it sits in the frame, and
    /// only when `CT_MOD_IP_V6` names the requester's own IPv6 beside it.
    #[test]
    fn the_dual_stack_record_is_read_by_its_ipv4_id_and_ipv6_tag() {
        let v4 = "45.55.200.8".parse().unwrap();
        let v6: std::net::Ipv6Addr = "3fff:ed2:1::8".parse().unwrap();
        // An IPv6-only record under the placeholder `1`, then the dual one.
        let mut frame = vec![0xc5, 0, 0, 0, 0, 0x84, 0x01];
        frame.extend_from_slice(&[0x11; 16]);
        frame.extend_from_slice(&[0x02, 0x00]);
        for id in [[1, 0, 0, 0], [45, 55, 200, 8]] {
            frame.extend_from_slice(&id);
            frame.extend_from_slice(&[0x36, 0x12, 0x02, 0x81, 0xae]);
            frame.extend_from_slice(&v6.octets());
            frame.extend_from_slice(&[0x81, 0xbc]);
            frame.extend_from_slice(&[0x5d; 16]);
        }

        let record = dual_stack_record(&frame, v4, v6).expect("the dual record is there");
        assert!(record.starts_with("2d37c80836120281ae3fff0ed2"));
        assert_eq!(
            dual_stack_record(&frame, v4, "3fff:ed2:1::9".parse().unwrap()),
            None
        );
    }
}
