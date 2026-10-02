//! `ipv6-download-rung0`: an rmule **download** takes rung 0 of the ADR-0061
//! route tree — a Low-ID source whose ExtSX record carries an IPv6 half
//! is dialled on that half before any callback is asked for it.
//!
//! emule-qt `73fff714` shares a one-part **Synthetic File** and is logged in to
//! `ed2ksrv`. A **Low-ID requester** (`ipv6 hold-slot`) reaches it over IPv6,
//! naming its own address in the hello, a Low ID, and `ed2ksrv` as its
//! server, and holds the upload slot. A real rmule `Core` then downloads the
//! file (`ed2k download start --serve`): it learns emule-qt from the server,
//! and its first file request carries the source ask. emule-qt answers out of
//! the clients it serves the file to (`KnownFile::createSrcInfoPacket`,
//! `KnownFile.cpp:761`), keeping a Low-ID client that named a reachable IPv6
//! on the ExtSX path (`:849`) and writing that client's server beside it
//! as `CT_EMULE_SERVERIP`/`SERVERTCP` (`:932-933`).
//!
//! Why this topology and not an existing leg: the claim must tell rung 0 from
//! the path that already existed. Every Low-ID + IPv6 record the other legs
//! produce reaches rmule's download as an **IPv6-only** source, pooled and
//! dialled like a High ID even before downloads ran rung 0 — rmule's own writer emits such a
//! client under the placeholder `1` (`ipv6-extsx-emit`), and emule-qt writes a
//! Low ID as `htonl(userIDHybrid)` (`KnownFile.cpp:870`), which rmule reads, as
//! emule-qt's own reader does (`PartFile.cpp:2844-2894`), as an unusable IPv4
//! and so rescues the IPv6 alone. A record reaches the download as a Low-ID
//! candidate *with* its half only when its id reads as a Low ID and its server
//! is ours (ADR-0055's Low-ID rule). So the requester's Low ID is
//! byte-palindromic under `htonl` — `0x00AAAA00` reads back as itself — and
//! its hello names `ed2ksrv`. Before downloads ran rung 0, that candidate took
//! the server callback and its IPv6 was never dialled; now the download's
//! `peer_selected` names the half first.
//!
//! The requester listens nowhere, so the dial is refused and the candidate
//! falls to its server callback — the fall-through is part of what the row
//! records: it lands tens of milliseconds before the one-part file
//! completes from emule-qt, so the leg needs no longer transfer, only the
//! download's own trace of it. The evidence is rmule's own trail
//! (`RmuleOnly`): the tap watches emule-qt's attachment, which the
//! downloader's dial never crosses.

use std::time::Duration;

use anyhow::{Context, Result};

use crate::docker::RunContainer;
use crate::flow::bench::Bench;
use crate::flow::ed2ksrv::Ed2ksrvImage;
use crate::flow::gate::wait_for_container_log;
use crate::flow::nat::dialect::bench::{
    HOST_ED2KSRV, HOST_EMULEQT, HOST_QUEUED, Ipv6DialectOptions, Stage, body_log, out, run_driver,
    start_detached_driver, wait_for_exit,
};
use crate::flow::nat::dialect::ext_sx::SLOT_MARKER;
use crate::flow::nat::dialect::legs::RMULE_USER_HASH;
use crate::flow::nat::dialect::verdict::{Body, Claim, DriverRow, Evidence};
use crate::flow::nat::dialect::{BODY_PEER_TCP_PORT, ED2KSRV_TCP_PORT};
use crate::flow::nat::synthetic::write_hashed;

/// One part, as every ExtSX leg shares.
const SHARED_BYTES: u64 = 1 << 20;

/// The requester's Low ID: under `0x01000000`, and its own byte reverse, so
/// emule-qt's `htonl(userIDHybrid)` writes the id rmule reads back.
const LOW_ID: u32 = 0x00AA_AA00;

/// The requester's user hash: distinct from rmule's, since emule-qt keys its
/// client list by hash.
const REQUESTER_USER_HASH: &str = "4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c";

/// The requester's container role.
const REQUESTER_ROLE: &str = "v6lowid";

/// How long the requester holds its slot: the downloader's whole run lands
/// inside it.
const HOLD_SECS: u64 = 150;

/// How long the downloader runs before its bounded exit.
const DOWNLOAD_SECS: u64 = 90;

/// emule-qt's readiness once logged in to the server, and its line once the
/// shared file is hashed — a file it has not hashed is not offered.
const EMULEQT_READY_MARKER: &str = "rmule-emuleqt-ready";
const EMULEQT_HASHED_MARKER: &str = "Hashed OK";

/// The downloader's event line for a worker put on a peer.
const PEER_SELECTED: &str = "download peer_selected";
/// The download's trace when a rung-0 dial ends unconnected and the Low-ID
/// candidate goes back to its callback roads.
const RUNG_0_FELL: &str =
    "rung-0 IPv6 dial failed; the Low-ID candidate falls to its callback roads";
/// Its trace as it hands a server callback (`0x1C`) to the connected server.
const CALLBACK_ASKED: &str = "server callback: asking the connected server to relay OP_CALLBACK";
/// The server session's trace on `OP_CALLBACK_FAIL` (`0x36`).
const CALLBACK_FAILED: &str = "server could not route a Low-ID callback";

/// Stand up the server and emule-qt, logged in and sharing the file. Returns
/// emule-qt's container, which the tap watches.
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
        "run the ed2k-server the downloader and emule-qt log in to",
    )?;

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
            .env("EMULEQT_CRYPT_REQUESTED", "true")
            .volume(
                shared
                    .path
                    .parent()
                    .context("the shared file has a directory")?,
                "/incoming",
            ),
        "run emule-qt logged in to the server, sharing the file",
    )?;
    wait_for_container_log(&bench.docker, &name, EMULEQT_READY_MARKER, timeout)?;
    wait_for_container_log(&bench.docker, &name, EMULEQT_HASHED_MARKER, timeout)?;

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
/// If a driver cannot start or its row cannot be read.
pub(super) fn drive(
    bench: &mut Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
) -> Result<(Vec<Claim>, String)> {
    let shared = stage.shared.as_ref().context("emule-qt shares a file")?;
    let requester_v6 = stage.v6(HOST_QUEUED).to_owned();
    let server = format!("{}:{ED2KSRV_TCP_PORT}", stage.v4(HOST_ED2KSRV));

    let hold = [
        "ipv6".to_owned(),
        "hold-slot".to_owned(),
        "--peer".to_owned(),
        format!("[{}]:{BODY_PEER_TCP_PORT}", stage.v6(HOST_EMULEQT)),
        "--file".to_owned(),
        shared.link.clone(),
        "--advertise-ipv6".to_owned(),
        requester_v6.clone(),
        "--client-id".to_owned(),
        LOW_ID.to_string(),
        "--connected-server".to_owned(),
        server.clone(),
        "--user-hash".to_owned(),
        REQUESTER_USER_HASH.to_owned(),
        "--capture".to_owned(),
        out("rung0-requester-capture"),
        "--out".to_owned(),
        out("rung0-requester.toml"),
        "--hold-secs".to_owned(),
        HOLD_SECS.to_string(),
    ];
    let (requester, slot_open) = start_detached_driver(
        bench,
        options,
        stage,
        REQUESTER_ROLE,
        HOST_QUEUED,
        &hold,
        SLOT_MARKER,
    )?;
    if !slot_open {
        wait_for_exit(bench, &requester)?;
        let row = DriverRow::read(&stage.leg_dir.join("rung0-requester.toml"))?;
        body_log(bench, stage, &requester, "rung0-requester-driver")?;
        return Ok((vec![requester_claim(&row, &requester_v6)], String::new()));
    }

    let download = [
        "ed2k",
        "download",
        "start",
        "--data-dir",
        &out("rung0-store"),
        "--server",
        &server,
        "--file",
        &shared.link,
        "--out",
        &out("rung0-download.bin"),
        "--serve",
        "--max-seconds",
        &DOWNLOAD_SECS.to_string(),
        "--user-hash",
        RMULE_USER_HASH,
    ]
    .map(str::to_owned);
    // A download that ends in failure is a measurement, not a broken bench:
    // its log is written either way, and the claim reads the log.
    let ran = run_driver(bench, options, stage, "rung0-download", &download);
    wait_for_exit(bench, &requester)?;
    let row = DriverRow::read(&stage.leg_dir.join("rung0-requester.toml"))?;
    body_log(bench, stage, &requester, "rung0-requester-driver")?;
    let download_log = std::fs::read_to_string(stage.leg_dir.join("rung0-download.log"))
        .context("read the downloader's log")?;

    Ok((
        vec![
            requester_claim(&row, &requester_v6),
            rung_0_claim(&download_log, &requester_v6, ran.err()),
            fell_through_claim(&download_log, &requester_v6),
        ],
        String::new(),
    ))
}

/// The requester is queued on emule-qt as a Low ID that named its IPv6 and its
/// server — the client emule-qt's ExtSX writer keeps and describes.
fn requester_claim(row: &DriverRow, requester_v6: &str) -> Claim {
    Claim::about(
        "a-low-id-requester-named-its-ipv6-and-server-and-holds-a-slot-on-emuleqt",
        !row.text("slot").is_empty(),
        Evidence::Captured,
        format!(
            "the requester reached emule-qt over IPv6 with Low ID 0x{LOW_ID:08X}, advertised \
             CT_MOD_IP_V6 [{requester_v6}] and ed2ksrv as its server, and emule-qt answered its \
             OP_STARTUPLOADREQ with slot={:?}; failure={:?}",
            row.text("slot"),
            row.text("failure"),
        ),
    )
}

/// The scored claim: the downloader put a worker on the Low-ID source's
/// IPv6 half — rung 0 — rather than only asking the server to call it back.
fn rung_0_claim(download_log: &str, requester_v6: &str, run_error: Option<anyhow::Error>) -> Claim {
    let half = format!("peer=[{requester_v6}]:{BODY_PEER_TCP_PORT}");
    let lines: Vec<&str> = download_log
        .lines()
        .filter(|line| line.contains(&half) && line.contains(PEER_SELECTED))
        .take(4)
        .collect();
    let selected = lines.iter().any(|line| line.contains(PEER_SELECTED));
    Claim::about(
        "rmule-download-dialled-the-low-id-sources-ipv6-half-first",
        selected,
        Evidence::RmuleOnly,
        format!(
            "the downloader's own lines for [{requester_v6}]:{BODY_PEER_TCP_PORT}: {lines:?} — a \
             worker on the half of a Low-ID source emule-qt described with our server, which \
             before downloads ran rung 0 took the server callback alone; run error: {:?}",
            run_error.map(|error| error.to_string()),
        ),
    )
}

/// The refused IPv6 dial gave way to the server callback for the
/// same source — the download's own fall line for the half and the Low ID,
/// then its `0x1C` request naming that Low ID. A worker's end on a dial that
/// never connected is no `peer_retired` event (that line is a verification
/// retirement's), so the fall reads the trace the state machine writes when it
/// re-pools the candidate. The server's `0x36` answer, if it came, is quoted
/// beside it: the requester is not logged in to `ed2ksrv`, so no callback can
/// be relayed.
fn fell_through_claim(download_log: &str, requester_v6: &str) -> Claim {
    let half = format!("peer=[{requester_v6}]:{BODY_PEER_TCP_PORT}");
    let low_id = format!("low_id={LOW_ID}");
    let lines: Vec<&str> = download_log.lines().collect();
    let fell = lines.iter().position(|line| {
        line.contains(RUNG_0_FELL) && line.contains(&half) && line.contains(&low_id)
    });
    let asked = fell.and_then(|at| {
        lines[at..]
            .iter()
            .position(|line| line.contains(CALLBACK_ASKED) && line.contains(&low_id))
            .map(|offset| at + offset)
    });
    let answered = asked.and_then(|at| {
        lines[at..]
            .iter()
            .find(|line| line.contains(CALLBACK_FAILED))
    });
    let quote = |at: Option<usize>| at.map(|at| lines[at].trim());
    Claim::about(
        "rung-0-fell-through-to-the-callback-road",
        asked.is_some(),
        Evidence::RmuleOnly,
        format!(
            "the downloader's fall line for [{requester_v6}]:{BODY_PEER_TCP_PORT} (Low ID \
             0x{LOW_ID:08X}): {:?}; its server-callback request for the same Low ID after it: \
             {:?}; the server's answer: {:?}",
            quote(fell),
            quote(asked),
            answered.map(|line| line.trim()),
        ),
    )
}
