//! `ipv6-extsx-emit`'s dual-stack fallback leg: an rmule **download**
//! whose first dial of a dual-stack source fails falls to that source's other
//! family once.
//!
//! A fourth requester is queued on the serving rmule over IPv4, its own
//! address as its High ID, and names in its hello an IPv6 **no bench network
//! routes** — an address on the Fake-Public v6 Plan's next `/64`, which no WAN
//! of this bench carries. rmule's serve pool keeps it as that client's IPv6
//! half, and rmule's ExtSX answer writes it beside the IPv4 id, as the
//! dual-stack leg shows on emule-qt's tap. A real rmule `Core` then
//! downloads the file (`ed2k download start --serve`, the `ipv6-download-rung0` downloader):
//! it learns the serving rmule from the server, and its first file request
//! carries the source ask. Holding a Known IPv6, its Dial Chooser picks the
//! half first; the WAN has no route there, so the dial never connects, and the
//! download dials the IPv4 half next.
//!
//! The evidence is the downloader's own trail (`RmuleOnly`): its two
//! `download.peer_selected` lines for the source, the half first and the IPv4
//! after it, with the fall trace between them. Before the other-family fallback the pool
//! held one address per source, and the second line never came.

use anyhow::{Context, Result};

use super::HOLD_SECS;
use crate::fake_public_v6::FakePublicV6Plan;
use crate::flow::bench::Bench;
use crate::flow::nat::dialect::bench::{
    HOST_DRIVER, HOST_ED2KSRV, HOST_EXTSX_DOWNLOADER, HOST_QUEUED_UNROUTABLE, Ipv6DialectOptions,
    Stage, body_log, out, start_detached_driver, wait_for_exit,
};
use crate::flow::nat::dialect::ext_sx::SLOT_MARKER;
use crate::flow::nat::dialect::verdict::{Claim, DriverRow, Evidence};
use crate::flow::nat::dialect::{BODY_PEER_TCP_PORT, ED2KSRV_TCP_PORT, WAN_V6_NET};

/// The unroutable requester's user hash: distinct from every other body's,
/// since rmule keys its sources by hello.
const UNROUTABLE_USER_HASH: &str = "7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b";

/// The unroutable requester's container role.
const UNROUTABLE_ROLE: &str = "v6unroutable";

/// The downloader's user hash: not the serving rmule's, which it dials.
const DOWNLOADER_USER_HASH: &str = "3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c";

/// The downloader's container role.
const DOWNLOADER_ROLE: &str = "v6fallback";

/// How long the downloader runs before its bounded exit — inside the
/// unroutable requester's hold, so the source is pooled on rmule throughout.
const DOWNLOAD_SECS: u64 = 60;

/// The downloader's line once a source answer is ingested.
const SOURCES_MARKER: &str = "download.sources_exchanged";

/// The downloader's event line for a worker put on a peer.
const PEER_SELECTED: &str = "download.peer_selected";

/// The download's trace when a dual-stack source's first dial ends
/// unconnected and its other family is dialed (`download/state/dual_stack.rs`).
const FELL: &str = "a dual-stack source's first-family dial failed; dialing its other family once";

/// Run the leg and return its claims. Started once the serving rmule has
/// answered emule-qt, so the earlier legs' answer is the one they measured.
///
/// # Errors
/// If a body cannot start or its log cannot be read.
pub(super) fn fallback_claims(
    bench: &mut Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
) -> Result<Vec<Claim>> {
    let half = unroutable_half()?;
    let (requester, slot_open) = start_unroutable_requester(bench, options, stage, &half)?;
    if !slot_open {
        wait_for_exit(bench, &requester)?;
        let row = DriverRow::read(&stage.leg_dir.join("extsx-unroutable.toml"))?;
        body_log(bench, stage, &requester, "extsx-unroutable-driver")?;
        return Ok(vec![requester_claim(stage, &half, &row)]);
    }

    let shared = stage.shared.as_ref().context("rmule shares a file")?;
    let download = [
        "ed2k",
        "download",
        "start",
        "--data-dir",
        &out("fallback-store"),
        "--server",
        &format!("{}:{ED2KSRV_TCP_PORT}", stage.v4(HOST_ED2KSRV)),
        "--file",
        &shared.link,
        "--out",
        &out("dl/fallback-download.bin"),
        "--serve",
        "--max-seconds",
        &DOWNLOAD_SECS.to_string(),
        "--user-hash",
        DOWNLOADER_USER_HASH,
    ]
    .map(str::to_owned);
    // A downloader that never ingests an answer is a measurement: the claim
    // reads its log either way.
    let (downloader, _) = start_detached_driver(
        bench,
        options,
        stage,
        DOWNLOADER_ROLE,
        HOST_EXTSX_DOWNLOADER,
        &download,
        SOURCES_MARKER,
    )?;
    for container in [&downloader, &requester] {
        wait_for_exit(bench, container)?;
    }
    let download_log = body_log(bench, stage, &downloader, "fallback-download")?;
    let row = DriverRow::read(&stage.leg_dir.join("extsx-unroutable.toml"))?;
    body_log(bench, stage, &requester, "extsx-unroutable-driver")?;

    Ok(vec![
        requester_claim(stage, &half, &row),
        fell_to_ipv4_claim(&download_log, &half, stage.v4(HOST_QUEUED_UNROUTABLE)),
    ])
}

/// The requester's IPv6 half: its own host index on the plan's next `/64`,
/// which no network of this bench carries, so no body has a route to it.
fn unroutable_half() -> Result<String> {
    let host = u16::try_from(HOST_QUEUED_UNROUTABLE).context("a host index fits a hextet")?;
    FakePublicV6Plan::for_network(WAN_V6_NET + 1)?.address(host)
}

/// Queue the unroutable requester on rmule: over IPv4, its own address as a
/// High ID, `half` named in the hello. Returns its container and whether rmule
/// granted or queued it.
fn start_unroutable_requester(
    bench: &mut Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
    half: &str,
) -> Result<(String, bool)> {
    let v4: std::net::Ipv4Addr = stage
        .v4(HOST_QUEUED_UNROUTABLE)
        .parse()
        .context("the unroutable requester's IPv4")?;
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
        half.to_owned(),
        // A High ID is the address in wire order: the octets read as a
        // little-endian word.
        "--client-id".to_owned(),
        u32::from_le_bytes(v4.octets()).to_string(),
        "--user-hash".to_owned(),
        UNROUTABLE_USER_HASH.to_owned(),
        "--capture".to_owned(),
        out("extsx-unroutable-capture"),
        "--out".to_owned(),
        out("extsx-unroutable.toml"),
        "--hold-secs".to_owned(),
        HOLD_SECS.to_string(),
        // Parts unknown, so rmule answers it to any asker (ADR-0055 §Serving).
        "--extended-requests".to_owned(),
        "0".to_owned(),
    ];
    start_detached_driver(
        bench,
        options,
        stage,
        UNROUTABLE_ROLE,
        HOST_QUEUED_UNROUTABLE,
        &hold,
        SLOT_MARKER,
    )
}

fn requester_claim(stage: &Stage, half: &str, row: &DriverRow) -> Claim {
    Claim::about(
        "a-dual-stack-requester-with-an-unroutable-ipv6-holds-a-place-on-rmule",
        !row.text("slot").is_empty(),
        Evidence::RmuleOnly,
        format!(
            "the requester reached rmule over IPv4 from {} with that address as its High ID, \
             advertised CT_MOD_IP_V6 [{half}] — on a /64 no bench network carries — and rmule \
             answered its OP_STARTUPLOADREQ with slot={:?}; failure={:?}",
            stage.v4(HOST_QUEUED_UNROUTABLE),
            row.text("slot"),
            row.text("failure"),
        ),
    )
}

/// The scored claim: the downloader put a worker on the source's
/// unroutable IPv6 half, and after it — once that dial failed — one on the
/// same source's IPv4 half. Held on the two `peer_selected` lines in that
/// order; the fall trace between them is quoted, not required.
fn fell_to_ipv4_claim(download_log: &str, half: &str, v4: &str) -> Claim {
    let at_half = format!("peer=[{half}]:{BODY_PEER_TCP_PORT}");
    let at_v4 = format!("peer={v4}:{BODY_PEER_TCP_PORT}");
    let lines: Vec<&str> = download_log.lines().collect();
    let selected = |from: usize, peer: &str| {
        lines[from..]
            .iter()
            .position(|line| line.contains(PEER_SELECTED) && line.contains(peer))
            .map(|offset| from + offset)
    };
    let first = selected(0, &at_half);
    let second = first.and_then(|at| selected(at + 1, &at_v4));
    let fell = lines
        .iter()
        .find(|line| line.contains(FELL) && line.contains(&at_half));
    let quote = |at: Option<usize>| at.map(|at| lines[at].trim());
    Claim::about(
        "a-failed-ipv6-dial-fell-to-the-ipv4-half",
        second.is_some(),
        Evidence::RmuleOnly,
        format!(
            "the downloader's worker on the unroutable half [{half}]:{BODY_PEER_TCP_PORT}: {:?}; \
             its fall line: {:?}; its worker on the same source's IPv4 half \
             {v4}:{BODY_PEER_TCP_PORT} after it: {:?}",
            quote(first),
            fell.map(|line| line.trim()),
            quote(second),
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::fell_to_ipv4_claim;

    const HALF: &str = "3fff:ed2:2::2";
    const V4: &str = "45.55.200.2";

    /// Held only on the half's worker *then* the IPv4's; an IPv4 worker put
    /// on the source before the half's is no fall.
    #[test]
    fn the_fall_is_the_halfs_worker_then_the_ipv4s() {
        let half_line = "download.peer_selected id=1 peer=[3fff:ed2:2::2]:4662";
        let v4_line = "download.peer_selected id=1 peer=45.55.200.2:4662";
        let held = |log: &str| fell_to_ipv4_claim(log, HALF, V4).outcome == "held";

        assert!(held(&format!("{half_line}\n{v4_line}\n")));
        assert!(!held(&format!("{v4_line}\n{half_line}\n")));
        assert!(!held(&format!(
            "{half_line}\ndownload.peer_selected id=1 peer=45.55.200.20:4662\n"
        )));
    }
}
