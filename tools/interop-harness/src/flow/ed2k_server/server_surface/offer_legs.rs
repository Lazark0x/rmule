//! The legs of `ed2ksrv-server-surface` that are about what rmule's production
//! session does on the pin, read off the server's tap: a real core publishing
//! a share past one batch under OFFERFILES v1 (ADR-0099), its opening
//! `OP_GETSERVERLIST` (ADR-0080), and a global `ed2k::HASH` answered with the
//! file (ADR-0034).

use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::flow::bench::{Bench, ED2K_SERVER_PORT};
use crate::flow::ed2k_server::rmule_tools::run_to_exit;
use crate::flow::ed2k_server::search_wire::ED2KSRV_IP;
use crate::flow::ed2k_server::search_wire::server_tap::{offers, opening};
use crate::flow::nat::claims::{Claim, Evidence};

/// The address the publishing core dials from.
const OFFER_IP: &str = "203.0.113.54";
/// A share past one of the server's batches, which `config-ipv6.toml` leaves
/// at its defaults: 200 records every 500 ms.
const OFFER_FILES: usize = 450;
const BATCH_MAX: u64 = 200;
const INTERVAL_MS: f64 = 500.0;
/// How far the tap's clock may read a gap short of the pace.
const GAP_SLACK: f64 = 0.8;
/// Seconds the core runs: the batches take about one.
const OFFER_RUN_SECS: &str = "15";
/// The directory the shared files sit in, under the leg's root.
const OFFER_DIR: &str = "offered";
const HASH_DIR: &str = "hash-search";

/// Run the core that publishes the share. Every frame lands on the server's tap.
pub(super) fn drive_offer(
    bench: &mut Bench,
    image: &str,
    ed2ksrv: &str,
    root: &Path,
) -> Result<()> {
    let dir = root.join(OFFER_DIR);
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let mut paths = Vec::with_capacity(OFFER_FILES);
    for index in 0..OFFER_FILES {
        let name = format!("offered-{index:04}.bin");
        fs::write(dir.join(&name), format!("rmule offer leg {index}"))
            .with_context(|| format!("write {name}"))?;
        paths.push(format!("/w/{OFFER_DIR}/{name}"));
    }
    let server = format!("{ED2KSRV_IP}:{ED2K_SERVER_PORT}");
    let mut args = vec!["ed2k", "serve", "start"];
    for path in &paths {
        args.extend(["--file", path.as_str()]);
    }
    args.extend([
        "--server",
        &server,
        "--listen",
        "0.0.0.0:4662",
        "--tcp-port",
        "4662",
        "--user-hash",
        "54545454545454545454545454545454",
        "--nickname",
        "server-surface",
        "--max-seconds",
        OFFER_RUN_SECS,
    ]);
    let name = format!("{ed2ksrv}-offer");
    run_to_exit(bench, image, &name, OFFER_IP, root, &args)?;
    bench.stop_extra(&name);
    Ok(())
}

/// Ask for `file_hash` by its hash over UDP, while its source is logged in.
pub(super) fn drive_hash_search(
    bench: &mut Bench,
    image: &str,
    ed2ksrv: &str,
    ip: &str,
    root: &Path,
    file_hash: &str,
) -> Result<()> {
    let server = format!("{ED2KSRV_IP}:{ED2K_SERVER_PORT}");
    let query = format!("ed2k::{file_hash}");
    let out = format!("/w/{HASH_DIR}");
    let args = [
        "ed2k",
        "server",
        "udp-capture",
        &server,
        "--out",
        &out,
        "--query",
        &query,
        "--timeout",
        "5",
    ];
    run_to_exit(bench, image, &format!("{ed2ksrv}-hash"), ip, root, &args)?;
    Ok(())
}

/// What the tap holds of the two legs.
#[derive(Debug, Default, PartialEq, Serialize)]
pub(crate) struct OfferRows {
    /// The core's login carried `offerfiles_v`.
    pub(crate) login_asked: bool,
    /// Its `OP_GETSERVERLIST` frames.
    pub(crate) list_asks: usize,
    /// `OP_SERVERIDENT` frames the server sent it.
    pub(crate) idents: usize,
    /// Of those, frames carrying the advertisement.
    pub(crate) adverts: usize,
    /// Records of each `OP_OFFERFILES`, in order.
    pub(crate) batches: Vec<u64>,
    /// Milliseconds between each batch and the next.
    pub(crate) gaps_ms: Vec<u64>,
    /// `0x99` datagrams naming the file a hash search asked for.
    pub(crate) hash_answers: usize,
}

/// Read both legs.
///
/// # Errors
/// If the tap cannot be read.
pub(crate) fn read_rows(pcap: &Path, root: &Path, file_hash: &str) -> Result<OfferRows> {
    let client: Ipv4Addr = OFFER_IP.parse()?;
    let seen = opening(pcap, client)?;
    let sent = offers(pcap, client)?;
    let hash = hex_bytes(file_hash);
    let hash_answers = fs::read_dir(root.join(HASH_DIR))
        .map(|dir| {
            dir.filter_map(|entry| entry.ok())
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with("search_res")
                })
                .filter_map(|entry| fs::read(entry.path()).ok())
                .filter(|bytes| bytes.windows(hash.len()).any(|at| at == hash))
                .count()
        })
        .unwrap_or_default();
    Ok(OfferRows {
        login_asked: seen.asked_pace,
        list_asks: seen.list_asks,
        idents: seen.idents,
        adverts: seen.adverts,
        batches: sent.iter().map(|(_, count)| *count).collect(),
        gaps_ms: sent
            .windows(2)
            .map(|pair| ((pair[1].0 - pair[0].0) * 1000.0).round() as u64)
            .collect(),
        hash_answers,
    })
}

fn hex_bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .filter_map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

/// Whether each gap is what its batch cost under the advertised bucket.
fn held_the_pace(rows: &OfferRows) -> bool {
    rows.batches.iter().zip(&rows.gaps_ms).all(|(batch, gap)| {
        *gap as f64 >= INTERVAL_MS * (*batch as f64 / BATCH_MAX as f64) * GAP_SLACK
    })
}

/// The claims over the two legs.
pub(crate) fn claims(rows: &OfferRows) -> Vec<Claim> {
    let told: u64 = rows.batches.iter().sum();
    let largest = rows.batches.iter().max().copied().unwrap_or(0);
    vec![
        Claim::about(
            "the-login-asked-and-the-first-ident-advertised",
            rows.login_asked && rows.idents == 1 && rows.adverts == 1,
            Evidence::Captured,
            format!(
                "asked={} idents={} adverts={}",
                rows.login_asked, rows.idents, rows.adverts
            ),
        ),
        Claim::about(
            "the-session-opened-with-one-server-list-ask",
            rows.list_asks == 1,
            Evidence::Captured,
            format!("{} OP_GETSERVERLIST", rows.list_asks),
        ),
        Claim::about(
            "the-whole-share-went-in-batches-at-the-advertised-pace",
            told == OFFER_FILES as u64
                && largest <= BATCH_MAX
                && rows.batches.len() > 1
                && held_the_pace(rows),
            Evidence::Captured,
            format!("batches {:?}, gaps {:?} ms", rows.batches, rows.gaps_ms),
        ),
        Claim::about(
            "a-global-hash-search-was-answered-with-the-file",
            rows.hash_answers > 0,
            Evidence::Captured,
            format!("{} 0x99 naming the file", rows.hash_answers),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A batch that left early fails the row even though the server would
    /// have held it back: the claim is that rmule read the advert.
    #[test]
    fn a_gap_counts_against_the_batch_before_it() {
        let rows = |gaps_ms: Vec<u64>| OfferRows {
            batches: vec![200, 200, 50],
            gaps_ms,
            ..OfferRows::default()
        };
        assert!(held_the_pace(&rows(vec![500, 498])));
        assert!(!held_the_pace(&rows(vec![500, 100])));
    }
}
