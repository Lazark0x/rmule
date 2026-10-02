//! `ipv6-extsx-kno`: kno's aMule `ab483654` as the second ExtSX oracle
//! ADR-0087 names — and what it answers instead.
//!
//! The shape is `ipv6-extsx`'s with kno in emule-qt's place: kno shares a
//! one-part **Synthetic File**, a **queued requester** that named its IPv6 in
//! its hello holds the slot kno grants, and a second rmule body asks kno for
//! sources. What kno answers is scored. Its source says what to expect — kno
//! never claims `EXTXS` (`AdvertisedModMiscOptions`, `PeerCapabilities.h:283`,
//! plus the IPv6 bit), nothing reads the peer's claim
//! (`SupportsExtendedSourceExchange` has no caller), and its only source-answer
//! writer (`CKnownFile::CreateSrcInfoPacket`, `KnownFile.cpp:1139-1330`)
//! writes classic fixed-stride records with no tag block, skipping every
//! source without an IPv4 wire form (`KnownFile.cpp:1219`). The advertised
//! IPv6 it read off the hello (`BaseClient.cpp:687-699`) feeds its own dialler
//! only (`BaseClient.cpp:2322-2325`). So the row this flow can take is a
//! **Documented Absence** measured on kno's own answer.
//!
//! Two constraints of this pin shape the bench. Every rmule body reaches kno
//! over **IPv4**: kno's first inbound native-IPv6 connection verifies its own
//! address, after which every hello answer counts a `CT_MOD_IP_V6` it does not
//! write (`ipv6-hello-tags`), which a strict reader refuses — so the queued requester is
//! dual-stack, queued over IPv4 with its IPv6 in the hello, and an
//! IPv6-connected requester is not stood up. The ask rides rmule's `0xA4`
//! bundle, whose `0x58` sub carries the asker's part status now that rmule
//! claims extended-requests 1. Measured first with a standalone
//! `OP_REQUESTSOURCES`: at the old v0 claim aMule cleared the asker's status on
//! the `0x58` sub (`UploadClient.cpp:199-205`) and refused the bundled ask on
//! the part-count check (`KnownFile.cpp:1169`).

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::docker::RunContainer;
use crate::flow::bench::Bench;
use crate::flow::gate::wait_for_container_log;
use crate::flow::nat::dialect::BODY_PEER_TCP_PORT;
use crate::flow::nat::dialect::bench::{
    HOST_AMULE_KNO, HOST_DRIVER, HOST_QUEUED_DUAL_STACK, Ipv6DialectOptions, Stage, body_log,
    container_name, out, run_driver, start_detached_driver, wait_for_exit,
};
use crate::flow::nat::dialect::ext_sx::{HOLD_SECS, QUEUED_USER_HASH, SLOT_MARKER};
use crate::flow::nat::dialect::legs::{RMULE_USER_HASH, hello_leg};
use crate::flow::nat::dialect::verdict::{Body, Claim, DriverRow, Evidence};
use crate::flow::nat::synthetic::write_hashed;

/// One part, as in `ipv6-extsx`: the part-count check then compares a
/// one-slot status against a one-part file.
const SHARED_BYTES: u64 = 1 << 20;

/// The stock direct-peer scenario's readiness line, which kno's entrypoint
/// hands over to under `AMULE_SCENARIO_MODE`.
const DIRECT_PEER_READY: &str = "rmule-amule-direct-peer-ready";

/// kno's own line once its hasher picked up the shared file
/// (`ThreadTasks.cpp:150`). There is no "done" line; a 1 MiB file hashes well
/// inside the bench's settle window.
const HASHING_MARKER: &str = "Hashing file";

/// Why the IPv6-connected half is not on this bench, carried in the verdict.
const NOTE: &str = "No IPv6-connected requester is stood up: kno's first inbound native-IPv6 \
    connection verifies its own address, after which its hello answer counts a CT_MOD_IP_V6 tag \
    it never writes (`ipv6-hello-tags`, BaseClient.cpp:1384 vs Tag.cpp:393), so every later rmule session \
    with kno is refused as malformed. By kno's source such a requester would be omitted \
    regardless: CreateSrcInfoPacket skips a source with no IPv4 wire form \
    (KnownFile.cpp:1219, PeerAddressing.h:107).";

/// Stand kno up in the direct-peer scenario sharing the synthetic file.
/// Returns its container, which the tap watches.
///
/// # Errors
/// If kno never becomes ready or never picks the file up.
pub(super) fn start(
    bench: &mut Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &mut Stage,
    suffix: &str,
    timeout: Duration,
) -> Result<String> {
    let dir: PathBuf = stage.leg_dir.join("shared");
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let shared = write_hashed(&dir, SHARED_BYTES)?;

    let kno = format!("rmule-interop-v6kno-{suffix}");
    bench.start_extra(
        &kno,
        RunContainer::new(options.amule_kno_image)
            .detach()
            .name(&kno)
            .network(&stage.network)
            .ip(stage.v4(HOST_AMULE_KNO))
            .ip6(stage.v6(HOST_AMULE_KNO))
            .cap_add("NET_ADMIN")
            .volume(&dir, "/incoming")
            .env("AMULE_SCENARIO_MODE", "direct-peer"),
        "run kno's aMule sharing the synthetic file",
    )?;
    wait_for_container_log(&bench.docker, &kno, DIRECT_PEER_READY, timeout)?;
    wait_for_container_log(&bench.docker, &kno, HASHING_MARKER, timeout)?;
    stage.bodies.push(Body {
        name: "amule-kno".to_owned(),
        image: options.amule_kno_image.to_owned(),
        pin: "kno/amule integration/network-parity ab483654".to_owned(),
        address_v4: stage.v4(HOST_AMULE_KNO).to_owned(),
        address_v6: stage.v6(HOST_AMULE_KNO).to_owned(),
    });
    stage.shared = Some(shared);
    Ok(kno)
}

/// Drive the flow and return its claims plus the standing note.
///
/// # Errors
/// If a driver container cannot run or its row cannot be read.
pub(super) fn drive(
    bench: &mut Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
) -> Result<(Vec<Claim>, String)> {
    let shared = stage.shared.as_ref().context("kno shares a file")?;
    let kno_peer = format!("{}:{BODY_PEER_TCP_PORT}", stage.v4(HOST_AMULE_KNO));
    let hello = hello_leg(
        bench,
        options,
        stage,
        "extsx-hello-amule-kno",
        &kno_peer,
        None,
    )?;
    let mut claims = vec![Claim::about(
        "amule-kno-claims-no-extsx",
        hello.int("hello_answer_bytes") > 0 && !hello.flag("claims_extsx"),
        Evidence::DocumentedAbsence,
        format!(
            "kno's OP_HELLOANSWER ({} bytes) carries CT_MOD_MISCOPTIONS word 0x{:04X} bits {:?}: \
             no EXTXS, so rmule never sends kno an ExtSX record, and kno has no ExtSX writer to \
             answer with (PeerCapabilities.h:283-294, :336)",
            hello.int("hello_answer_bytes"),
            hello.int("mod_misc_word"),
            hello.text("mod_misc_bits"),
        ),
    )];

    let queued_v4 = stage.v4(HOST_QUEUED_DUAL_STACK).to_owned();
    let queued_v6 = stage.v6(HOST_QUEUED_DUAL_STACK).to_owned();
    let body_args = |leg: &str, v6: &str, hash: &str| {
        vec![
            "--peer".to_owned(),
            kno_peer.clone(),
            "--file".to_owned(),
            shared.link.clone(),
            "--advertise-ipv6".to_owned(),
            v6.to_owned(),
            "--user-hash".to_owned(),
            hash.to_owned(),
            "--capture".to_owned(),
            out(&format!("{leg}-capture")),
            "--out".to_owned(),
            out(&format!("{leg}.toml")),
        ]
    };
    let mut hold = vec!["ipv6".to_owned(), "hold-slot".to_owned()];
    hold.extend(body_args("extsx-queued", &queued_v6, QUEUED_USER_HASH));
    hold.extend(["--hold-secs".to_owned(), HOLD_SECS.to_string()]);
    // The queued requester holds nothing. Claiming extended requests it would
    // say so, and the answerer lists a source only when it holds a part the
    // asker lacks or reports no status at all (aMule `CreateSrcInfoPacket`,
    // emule-qt `sourceHasNeededPart`) — so it claims `0`, as every rmule body
    // did when this flow was measured.
    hold.extend(["--extended-requests".to_owned(), "0".to_owned()]);
    let (queued_container, slot_open) = start_detached_driver(
        bench,
        options,
        stage,
        "v6queued",
        HOST_QUEUED_DUAL_STACK,
        &hold,
        SLOT_MARKER,
    )?;
    let kno = container_name(options.layout, "v6kno")?;
    if !slot_open {
        wait_for_exit(bench, &queued_container)?;
        let queued = DriverRow::read(&stage.leg_dir.join("extsx-queued.toml"))?;
        body_log(bench, stage, &queued_container, "extsx-queued-driver")?;
        body_log(bench, stage, &kno, "amule-kno-body")?;
        claims.push(Claim::about(
            "a-dual-stack-requester-named-its-ipv6-and-holds-a-slot",
            false,
            Evidence::Captured,
            format!(
                "kno never granted or queued the requester at {queued_v4}: identified={} \
                 failure={:?}",
                queued.flag("identified"),
                queued.text("failure"),
            ),
        ));
        return Ok((claims, NOTE.to_owned()));
    }

    let mut ask = vec!["ipv6".to_owned(), "sx-ask".to_owned()];
    ask.extend(body_args(
        "extsx-ask",
        stage.v6(HOST_DRIVER),
        RMULE_USER_HASH,
    ));
    run_driver(bench, options, stage, "extsx-ask", &ask)?;
    wait_for_exit(bench, &queued_container)?;
    let queued = DriverRow::read(&stage.leg_dir.join("extsx-queued.toml"))?;
    let asked = DriverRow::read(&stage.leg_dir.join("extsx-ask.toml"))?;
    body_log(bench, stage, &queued_container, "extsx-queued-driver")?;
    body_log(bench, stage, &kno, "amule-kno-body")?;

    let queued_source = format!("{queued_v4}:{BODY_PEER_TCP_PORT}");
    let records = asked.list("records");
    let session_sources = asked.list("session_sources");
    claims.extend([
        Claim::about(
            "a-dual-stack-requester-named-its-ipv6-and-holds-a-slot",
            !queued.text("slot").is_empty(),
            Evidence::Captured,
            format!(
                "the queued requester reached kno over IPv4 from {queued_v4}, advertised \
                 CT_MOD_IP_V6 [{queued_v6}], and kno answered its OP_STARTUPLOADREQ with \
                 slot={:?} ({} bytes served); failure={:?}",
                queued.text("slot"),
                queued.int("bytes_received"),
                queued.text("failure"),
            ),
        ),
        Claim::about(
            "amule-kno-answered-the-bundled-source-ask",
            asked.int("answer_bytes") > 0 && asked.text("decode_error").is_empty(),
            Evidence::Captured,
            format!(
                "rmule's 0xA4 bundle (its 0x58 sub carrying its part status) drew {} {} bytes \
                 ({}), SX1 nibble {}; decode error {:?}. Answer bytes: {}",
                asked.text("answer_opcode"),
                asked.int("answer_bytes"),
                asked.text("answer_protocol"),
                asked.int("peer_sx1_version"),
                asked.text("decode_error"),
                asked.text("answer_hex"),
            ),
        ),
        Claim::about(
            "amule-kno-writes-no-extsx-record",
            asked.int("record_count") > 0
                && asked.list("ipv6_sources").is_empty()
                && matches!(asked.text("answer_opcode").as_str(), "0x82" | "0x84"),
            Evidence::DocumentedAbsence,
            format!(
                "{} classic record(s) {records:?} and no IPv6 half: kno lists the queued \
                 requester by its IPv4 hybrid id and drops the IPv6 its hello named — the \
                 record has no tag block to carry it (KnownFile.cpp:1278-1308)",
                asked.int("record_count"),
            ),
        ),
        // rmule's own consume of the same frame: Stimulus about rmule.
        Claim::about(
            "rmule-surfaces-the-classic-source",
            session_sources
                .iter()
                .any(|endpoint| endpoint == &queued_source),
            Evidence::RmuleOnly,
            format!("the session's SourcesReceived carried {session_sources:?}"),
        ),
    ]);
    Ok((claims, NOTE.to_owned()))
}
