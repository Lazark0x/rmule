//! `ipv6-extsx-core`: rmule's **production requester** asks stock aMule 2.3.3
//! for sources.
//!
//! `ipv6-extsx-kno`'s shape with the stock image in kno's place, and a server under it so
//! the asker is rmule's real `Core` rather than a driver: stock aMule shares a
//! one-part **Synthetic File** logged in to `ed2ksrv`, a **queued requester**
//! holds a slot on it, and `rmule-tools ed2k download start` finds aMule
//! through the server and opens the file with its connect-time `0xA4` bundle.
//!
//! What the flow settles is the extended-requests rule. Before it, rmule claimed
//! extended-requests v0, so the bundle's `0x58` sub made aMule clear the
//! asker's part status (`UploadClient.cpp:397-406`, stock 2.3.3) and
//! `CKnownFile::CreateSrcInfoPacket` refused a complete file's answer on the
//! part-count check (`KnownFile.cpp:929`). rmule now claims v1 and writes its
//! part status after the `0x58` sub, so the answer can come.
//!
//! The queued requester claims extended-requests `0` (a capture override): it
//! holds nothing, and aMule lists a source only when it holds a part the asker
//! lacks or reports no status at all (`KnownFile.cpp:977-998`). A v1 requester
//! holding nothing would be dropped, and the answer would be `NULL` for a
//! reason that is not rmule's ask.

use std::fs;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::docker::RunContainer;
use crate::flow::bench::{Bench, CAPTURE_MOUNT};
use crate::flow::ed2ksrv::ED2KSRV;
use crate::flow::evidence::write_pcap_all_matches;
use crate::flow::gate::wait_for_container_log;
use crate::flow::nat::dialect::bench::{
    HOST_DRIVER, HOST_ED2KSRV, HOST_LEGACY_AMULE, HOST_QUEUED, Ipv6DialectOptions, Stage, body_log,
    container_name, out, start_detached_driver, wait_for_exit,
};
use crate::flow::nat::dialect::ext_sx::{QUEUED_USER_HASH, SLOT_MARKER};
use crate::flow::nat::dialect::legs::RMULE_USER_HASH;
use crate::flow::nat::dialect::verdict::{Body, Claim, DriverRow, Evidence};
use crate::flow::nat::dialect::{BODY_PEER_TCP_PORT, ED2KSRV_TCP_PORT};
use crate::flow::nat::synthetic::write_hashed;
use crate::flow::pcap::{Ed2kFrame, TcpStream, tcp_streams};

/// One part: the complete-file ask that rule is about, and a `0x58` status of
/// `01 00 00` (aMule's `size / PARTSIZE + 1` count, nothing held).
const SHARED_BYTES: u64 = 1 << 20;

/// The stock image's readiness line once logged in to the server with its
/// shared directory listed.
const AMULE_READY: &str = "rmule-amule-ready";

/// How long the queued requester holds its slot: it spans the downloader's
/// login, its source lookup and its dial.
const HOLD_SECS: u64 = 120;

/// The downloader's bound: one part completes in seconds, and the deadline
/// keeps a run that never draws an answer from waiting on nothing.
const CORE_SECS: u64 = 90;

/// The downloader prints this once a source answer decoded
/// (`DownloadEvent::SourcesExchanged`).
const EXCHANGED_MARKER: &str = "download.sources_exchanged";

/// Why the flow's queued requester claims extended-requests 0, for the verdict.
const NOTE: &str = "The queued requester claims extended-requests 0 by capture override: it \
    holds nothing, and stock aMule lists a source to an asker whose status it knows only when \
    that source holds a part the asker lacks, or reports no status (KnownFile.cpp:977-998). \
    rmule's own downloader claims the shipped v1.";

/// Stand up the server and stock aMule sharing the synthetic file. Returns
/// aMule's container, which the tap watches.
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
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let shared = write_hashed(&dir, SHARED_BYTES)?;
    let server_v4 = stage.v4(HOST_ED2KSRV).to_owned();

    let server = format!("rmule-interop-v6srv-{suffix}");
    let ed2ksrv = ED2KSRV.check(&bench.docker, options.ed2ksrv_image)?;
    bench.start_extra(
        &server,
        ed2ksrv
            .container()
            .detach()
            .name(&server)
            .network(&stage.network)
            .ip(&server_v4)
            .ip6(stage.v6(HOST_ED2KSRV))
            .cap_add("NET_ADMIN"),
        "run the ed2k-server both clients log in to",
    )?;

    let amule = format!("rmule-interop-v6stock-{suffix}");
    bench.start_extra(
        &amule,
        RunContainer::new(options.amule_image)
            .detach()
            .name(&amule)
            .network(&stage.network)
            .ip(stage.v4(HOST_LEGACY_AMULE))
            .ip6(stage.v6(HOST_LEGACY_AMULE))
            .cap_add("NET_ADMIN")
            .volume(&dir, "/incoming")
            .env("AMULE_SCENARIO_MODE", "ed2k-server")
            .env("AMULE_SHARED_DIR", "/incoming")
            .env("ED2K_SERVER_HOST", &server_v4)
            .env("ED2K_SERVER_PORT", ED2KSRV_TCP_PORT.to_string()),
        "run stock aMule 2.3.3 sharing the synthetic file",
    )?;
    wait_for_container_log(&bench.docker, &amule, AMULE_READY, timeout)?;

    stage.bodies.extend([
        Body {
            name: "amule".to_owned(),
            image: options.amule_image.to_owned(),
            pin: "aMule 2.3.3, Ubuntu 24.04 package".to_owned(),
            address_v4: stage.v4(HOST_LEGACY_AMULE).to_owned(),
            address_v6: String::new(),
        },
        Body {
            name: "ed2ksrv".to_owned(),
            image: options.ed2ksrv_image.to_owned(),
            pin: ed2ksrv.pin(),
            address_v4: server_v4,
            address_v6: String::new(),
        },
    ]);
    stage.shared = Some(shared);
    Ok(amule)
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
    let shared = stage.shared.as_ref().context("aMule shares a file")?;
    let amule_v4 = stage.v4(HOST_LEGACY_AMULE).to_owned();
    let core_v4 = stage.v4(HOST_DRIVER).to_owned();
    let queued_v4 = stage.v4(HOST_QUEUED).to_owned();
    let amule = container_name(options.layout, "v6stock")?;

    let hold = [
        "ipv6",
        "hold-slot",
        "--peer",
        &format!("{amule_v4}:{BODY_PEER_TCP_PORT}"),
        "--file",
        &shared.link,
        "--user-hash",
        QUEUED_USER_HASH,
        "--extended-requests",
        "0",
        "--capture",
        &out("core-queued-capture"),
        "--out",
        &out("core-queued.toml"),
        "--hold-secs",
        &HOLD_SECS.to_string(),
    ]
    .map(str::to_owned);
    let (queued_container, slot_open) = start_detached_driver(
        bench,
        options,
        stage,
        "v6queued",
        HOST_QUEUED,
        &hold,
        SLOT_MARKER,
    )?;
    if !slot_open {
        wait_for_exit(bench, &queued_container)?;
        let queued = DriverRow::read(&stage.leg_dir.join("core-queued.toml"))?;
        body_log(bench, stage, &queued_container, "core-queued-driver")?;
        body_log(bench, stage, &amule, "amule-body")?;
        return Ok((
            vec![queued_claim(&queued, &queued_v4, false)],
            NOTE.to_owned(),
        ));
    }

    let download = [
        "ed2k",
        "download",
        "start",
        "--data-dir",
        &out("core-data"),
        "--server",
        &format!("{}:{ED2KSRV_TCP_PORT}", stage.v4(HOST_ED2KSRV)),
        "--file",
        &shared.link,
        "--out",
        &out("dl/core-download.bin"),
        "--tcp-port",
        &BODY_PEER_TCP_PORT.to_string(),
        "--user-hash",
        RMULE_USER_HASH,
        "--serve",
        "--max-seconds",
        &CORE_SECS.to_string(),
    ]
    .map(str::to_owned);
    let (core_container, exchanged) = start_detached_driver(
        bench,
        options,
        stage,
        "v6core",
        HOST_DRIVER,
        &download,
        EXCHANGED_MARKER,
    )?;
    wait_for_exit(bench, &core_container)?;
    wait_for_exit(bench, &queued_container)?;
    let core_log = body_log(bench, stage, &core_container, "core-downloader")?;
    let queued = DriverRow::read(&stage.leg_dir.join("core-queued.toml"))?;
    body_log(bench, stage, &queued_container, "core-queued-driver")?;
    body_log(bench, stage, &amule, "amule-body")?;

    let asked = lift_frames(
        bench,
        options,
        stage,
        &format!("src host {core_v4} and dst host {amule_v4} and dst port {BODY_PEER_TCP_PORT}"),
        "core-to-amule.pcap",
    )?;
    let answered = lift_frames(
        bench,
        options,
        stage,
        &format!("src host {amule_v4} and src port {BODY_PEER_TCP_PORT} and dst host {core_v4}"),
        "amule-to-core.pcap",
    )?;
    let bundle = asked
        .into_iter()
        .find(|frame| frame.protocol == 0xC5 && frame.opcode == 0xA4);
    let status = bundle
        .as_ref()
        .and_then(|frame| name_sub_status(frame.payload()));
    let answer = answered
        .into_iter()
        .find(|frame| frame.protocol == 0xC5 && matches!(frame.opcode, 0x82 | 0x84));
    let listed = answer
        .as_ref()
        .and_then(|frame| answer_sources(frame.opcode, frame.payload()))
        .unwrap_or_default();
    let exchanged_line = core_log
        .lines()
        .find(|line| line.contains(EXCHANGED_MARKER))
        .unwrap_or_default()
        .to_owned();
    let queued_source = format!("{queued_v4}:{BODY_PEER_TCP_PORT}");

    let claims = vec![
        queued_claim(&queued, &queued_v4, true),
        Claim::about(
            "rmule-core-asks-with-its-part-status",
            status.as_ref().is_some_and(|status| {
                status.count == 1 && status.bitmap == [0x00] && status.next_sub == Some(0x83)
            }),
            Evidence::Captured,
            format!(
                "rmule's downloader opened the file with {}; its 0x58 sub carries {status:?} \
                 (expected count 1, bitmap [00] — one part, nothing held — then the SX2 ask)",
                bundle.as_ref().map_or_else(
                    || "no 0xA4 bundle on the tap".to_owned(),
                    |frame| format!("a {}-byte 0xA4 bundle", frame.payload().len()),
                ),
            ),
        ),
        Claim::about(
            "stock-amule-answers-rmule-core-for-a-complete-file",
            answer.is_some(),
            Evidence::Captured,
            format!(
                "aMule's answer on the tap: {}",
                answer.as_ref().map_or_else(
                    || "none — no OP_ANSWERSOURCES(2) toward the downloader".to_owned(),
                    |frame| format!("opcode 0x{:02X}, {}", frame.opcode, hex(frame.payload())),
                ),
            ),
        ),
        Claim::about(
            "the-answer-names-the-queued-requester",
            listed.iter().any(|source| source == &queued_source),
            Evidence::Captured,
            format!(
                "the answer's records name {listed:?}; the queued requester is {queued_source}"
            ),
        ),
        Claim::about(
            "rmule-core-decodes-the-answer",
            exchanged && exchanged_line.contains(&format!("peer={amule_v4}:{BODY_PEER_TCP_PORT}")),
            Evidence::RmuleOnly,
            format!("the downloader's own line: {exchanged_line:?}"),
        ),
    ];
    Ok((claims, NOTE.to_owned()))
}

fn queued_claim(queued: &DriverRow, queued_v4: &str, slot_open: bool) -> Claim {
    Claim::about(
        "a-v0-requester-holds-a-slot-on-stock-amule",
        slot_open && !queued.text("slot").is_empty(),
        Evidence::Captured,
        format!(
            "the queued requester at {queued_v4} (extended-requests 0) got slot={:?}; \
             identified={} failure={:?}",
            queued.text("slot"),
            queued.flag("identified"),
            queued.text("failure"),
        ),
    )
}

/// The eD2k frames of one direction of the downloader's link to aMule, its
/// segments lifted off the tap into `name` and reassembled.
fn lift_frames(
    bench: &Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
    link: &str,
    name: &str,
) -> Result<Vec<Ed2kFrame>> {
    let tap = format!("{}-wan", container_name(options.layout, "v6tap")?);
    let pcap = format!("{CAPTURE_MOUNT}/tap-wan.pcap");
    write_pcap_all_matches(
        &bench.docker,
        &tap,
        &pcap,
        &format!("tcp and ({link})"),
        name,
    )?;
    Ok(tcp_streams(&stage.leg_dir.join(name))?
        .iter()
        .flat_map(TcpStream::ed2k_frames)
        .collect())
}

/// What a `0xA4` bundle's name sub carried.
#[derive(Debug, PartialEq, Eq)]
struct NameSubStatus {
    /// The `u16` part count after the `0x58`.
    count: u16,
    /// The bitmap bytes that count implies.
    bitmap: Vec<u8>,
    /// The sub-opcode right after them.
    next_sub: Option<u8>,
}

/// Read the part status after an `0xA4` bundle's leading `0x58` sub:
/// `<hash 16><size 8> 58 <u16 count><bitmap>`, then the next sub-opcode.
fn name_sub_status(payload: &[u8]) -> Option<NameSubStatus> {
    let name = 16 + 8;
    if payload.get(name) != Some(&0x58) {
        return None;
    }
    let count = u16::from_le_bytes([*payload.get(name + 1)?, *payload.get(name + 2)?]);
    let end = name + 3 + usize::from(count).div_ceil(8);
    Some(NameSubStatus {
        count,
        bitmap: payload.get(name + 3..end)?.to_vec(),
        next_sub: payload.get(end).copied(),
    })
}

/// The `a.b.c.d:port` of each record in a source answer: `0x84` opens with a
/// version byte, `0x82` does not; then `<hash 16><u16 count>` and records whose
/// first six bytes are `<id 4><port 2>`. At version ≥ 3 the id is aMule's
/// `GetUserIDHybrid()` written little-endian (`KnownFile.cpp:1281-1286`), so a
/// High ID's octets arrive reversed; below 3 it is `GetIP()`, in wire order. The
/// stride is 29 bytes at v4, 28 below.
fn answer_sources(opcode: u8, payload: &[u8]) -> Option<Vec<String>> {
    let (version, body) = match opcode {
        0x84 => (*payload.first()?, payload.get(1..)?),
        _ => (3, payload),
    };
    let count = u16::from_le_bytes([*body.get(16)?, *body.get(17)?]);
    let stride = if version >= 4 { 29 } else { 28 };
    (0..usize::from(count))
        .map(|index| {
            let record = body.get(18 + index * stride..18 + index * stride + 6)?;
            let mut octets = [record[0], record[1], record[2], record[3]];
            if version >= 3 {
                octets.reverse();
            }
            Some(format!(
                "{}:{}",
                std::net::Ipv4Addr::from(octets),
                u16::from_le_bytes([record[4], record[5]])
            ))
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::{NameSubStatus, answer_sources, name_sub_status};

    #[test]
    fn the_name_sub_status_is_read_from_after_the_bundle_header() {
        let mut payload = vec![0xAB; 24];
        payload.extend_from_slice(&[0x58, 0x03, 0x00, 0b010, 0x4F, 0x83, 0x04, 0x00, 0x00]);
        assert_eq!(
            name_sub_status(&payload),
            Some(NameSubStatus {
                count: 3,
                bitmap: vec![0b010],
                next_sub: Some(0x4F)
            })
        );
        payload[24] = 0x83;
        assert_eq!(name_sub_status(&payload), None);
    }

    #[test]
    fn an_sx2_v4_answer_names_each_record_by_its_hybrid_id() {
        // Stock aMule 2.3.3's answer to rmule's downloader, `ipv6-extsx-core` run
        // `1790221409`: the queued requester 45.55.200.7 as `07c8372d`.
        let payload = [
            &[4][..],
            &[0x11; 16],
            &1u16.to_le_bytes(),
            &[0x07, 0xC8, 0x37, 0x2D, 0x36, 0x12],
            &[0; 23],
        ]
        .concat();
        assert_eq!(
            answer_sources(0x84, &payload),
            Some(vec!["45.55.200.7:4662".to_owned()])
        );
    }
}
