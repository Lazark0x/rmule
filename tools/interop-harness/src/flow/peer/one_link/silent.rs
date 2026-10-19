//! The one-link flow's **silent** leg: a second stock aMule sharer is frozen
//! (`docker pause`) once it has logged in and offered both files, so the
//! server still names it as a source while nothing in it answers. Its kernel
//! still takes a TCP connect onto the listen backlog, so rmule's obfuscated
//! dial is accepted and then meets silence: no key answer, no hello. rmule
//! runs under `--peer-crypt requested`, so every dial to an aMule the server
//! names with its User Hash goes out obfuscated.
//!
//! aMule's socket timeout covers a socket from its connect through the crypt
//! handshake: `CONNECTION_TIMEOUT`, 40 s (`protocol/ed2k/Constants.h:34`,
//! `ClientTCPSocket.cpp:201-222`). rmule's crypt handshake timeout takes the
//! same 40 s and ends the dial as `crypt_unanswered`. The silent side is a frozen stock aMule, not a fake
//! written from source reading: what it does is nothing, which any listener
//! that accepts and never answers does. The live sharer is the control: its
//! obfuscated dial completes and carries both files.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::verdict::{RMULE_PCAP, ROOT_DIR, SECOND_FILE};
use crate::flow::bench::AMULE_PEER_TCP_PORT;
use crate::flow::nat::claims::{Claim, Evidence, label};
use crate::flow::pcap::{TcpCapture, records, tcp_capture};

/// The verdict file this leg writes.
pub(crate) const VERDICT: &str = "peer-one-link-silent-verdict.toml";
/// The addresses this leg writes beside the flow's own.
const SILENT_ADDRESSES: &str = "silent.toml";
/// The crypt handshake timeout the dial is held to (aMule's
/// `CONNECTION_TIMEOUT`), and the slack either side of it the claim allows.
const CRYPT_TIMEOUT_SECS: f64 = 40.0;
const CRYPT_TIMEOUT_SLACK_SECS: f64 = 5.0;

/// rmule's dial to the frozen sharer went out obfuscated and drew no byte.
pub(crate) const OBFUSCATED_INTO_SILENCE: &str =
    "rmule-dialed-the-silent-sharer-obfuscated-and-heard-nothing";
/// That dial ended as `crypt_unanswered` at about the crypt timeout.
pub(crate) const CRYPT_UNANSWERED: &str = "the-silent-dial-ended-crypt-unanswered-at-about-40-s";
/// The live sharer's obfuscated dial connected and carried both files.
pub(crate) const LIVE_CRYPT: &str = "the-live-sharers-obfuscated-dial-connected-and-carried-both";

/// The three bodies' addresses, written by the flow.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct SilentAddresses {
    /// rmule's address.
    pub(crate) rmule: Ipv4Addr,
    /// The live sharer's address.
    pub(crate) sharer: Ipv4Addr,
    /// The frozen sharer's address.
    pub(crate) silent: Ipv4Addr,
}

impl SilentAddresses {
    /// Write them under the flow's dir `dir`.
    pub(crate) fn write(&self, dir: &Path) -> Result<()> {
        let path = dir.join(SILENT_ADDRESSES);
        fs::write(&path, toml::to_string(self).context("serialize addresses")?)
            .with_context(|| format!("write {}", path.display()))
    }
}

/// The rows beside the claims.
#[derive(Debug, Default, Serialize, PartialEq)]
struct Rows {
    /// The capture time of rmule's first SYN to the frozen sharer (`-1`
    /// without one), the time of its first `download.dial_ended` for it, and
    /// the seconds between them.
    silent_dial_opened_at: f64,
    silent_dial_ended_at: f64,
    silent_dial_secs: f64,
    /// The causes of every `download.dial_ended` for the frozen sharer.
    silent_dial_causes: Vec<String>,
    /// rmule's SYNs to the frozen sharer.
    silent_dials: usize,
    /// Bytes rmule wrote toward the frozen sharer on its first dial, and
    /// whether they opened with an eD2k header; bytes the frozen sharer wrote back.
    silent_bytes_out: usize,
    silent_dial_plain: bool,
    silent_bytes_back: usize,
    /// Whether rmule's first dial to the live sharer opened with an eD2k
    /// header, and the bytes the live sharer wrote back on it.
    live_dial_plain: bool,
    live_bytes_back: usize,
    /// Whether each copy is byte-equal to its staged file.
    copies_equal: [bool; 2],
}

/// The verdict file.
#[derive(Debug, Serialize)]
struct Verdict<'a> {
    #[serde(rename = "scenario")]
    flow: &'static str,
    verdict: &'static str,
    detail: String,
    rows: &'a Rows,
    claim: &'a [Claim],
}

/// Every `download.dial_ended` for `peer`: its cause and its time.
fn dial_ends(log: &str, peer: SocketAddr) -> Vec<(String, f64)> {
    let peer = format!("peer={peer}");
    log.lines()
        .filter(|line| line.starts_with("download.dial_ended "))
        .filter(|line| line.split_whitespace().any(|field| field == peer))
        .filter_map(|line| {
            let field = |key: &str| {
                line.split_whitespace()
                    .find_map(|field| field.strip_prefix(key))
            };
            let at = field("at_unix_ms=")?.parse::<f64>().ok()? / 1000.0;
            Some((field("cause=")?.to_owned(), at))
        })
        .collect()
}

/// rmule's first stream toward `peer` and the stream back on the same link:
/// bytes out, whether they open plain, bytes back.
fn first_link(capture: &TcpCapture, rmule: IpAddr, peer: SocketAddr) -> (usize, bool, usize) {
    let Some(out) = capture
        .streams
        .iter()
        .filter(|stream| stream.source.ip() == rmule && stream.destination == peer)
        .min_by(|a, b| a.opened_at().total_cmp(&b.opened_at()))
    else {
        return (0, false, 0);
    };
    let back = capture
        .streams
        .iter()
        .find(|stream| stream.source == out.destination && stream.destination == out.source)
        .map_or(0, |stream| stream.bytes.len());
    (out.bytes.len(), out.opens_plain(), back)
}

/// Score the silent run under `run_dir` and write `VERDICT`; the verdict.
///
/// # Errors
/// If the addresses, the tap, the staged files or rmule's log cannot be read.
pub fn score_run_dir(run_dir: &Path) -> Result<&'static str> {
    let root = run_dir.join(ROOT_DIR);
    let at: SilentAddresses = toml::from_str(
        &fs::read_to_string(root.join(SILENT_ADDRESSES)).context("read silent.toml")?,
    )
    .context("parse silent.toml")?;
    let capture = tcp_capture(&records(&root.join(RMULE_PCAP))?)?;
    let log_path = run_dir.join("rmule").join("stdout.log");
    let log =
        fs::read_to_string(&log_path).with_context(|| format!("read {}", log_path.display()))?;
    let rmule = IpAddr::V4(at.rmule);
    let silent = SocketAddr::from((at.silent, AMULE_PEER_TCP_PORT));
    let live = SocketAddr::from((at.sharer, AMULE_PEER_TCP_PORT));

    let syns: Vec<f64> = capture
        .opens
        .iter()
        .filter(|open| open.source.ip() == rmule && open.destination == silent)
        .map(|open| open.at)
        .collect();
    let opened = syns.iter().copied().reduce(f64::min);
    let ends = dial_ends(&log, silent);
    let first_end = ends.first().map(|(_, end)| *end);
    let (silent_bytes_out, silent_dial_plain, silent_bytes_back) =
        first_link(&capture, rmule, silent);
    let (_, live_dial_plain, live_bytes_back) = first_link(&capture, rmule, live);
    let synthetic = run_dir.join("synthetic");
    let equal = |staged: &str, written: &str| -> Result<bool> {
        let staged = synthetic.join(staged);
        let staged = fs::read(&staged).with_context(|| format!("read {}", staged.display()))?;
        Ok(fs::read(run_dir.join("rmule").join(written)).is_ok_and(|copy| copy == staged))
    };
    let rows = Rows {
        silent_dial_opened_at: opened.unwrap_or(-1.0),
        silent_dial_ended_at: first_end.unwrap_or(-1.0),
        silent_dial_secs: opened
            .zip(first_end)
            .map_or(-1.0, |(opened, ended)| ended - opened),
        silent_dial_causes: ends.iter().map(|(cause, _)| cause.clone()).collect(),
        silent_dials: syns.len(),
        silent_bytes_out,
        silent_dial_plain,
        silent_bytes_back,
        live_dial_plain,
        live_bytes_back,
        copies_equal: [
            equal("shared.bin", "output.bin")?,
            equal(SECOND_FILE, "output-2.bin")?,
        ],
    };
    let first_cause = rows
        .silent_dial_causes
        .first()
        .map_or("none", String::as_str);
    let claims = vec![
        Claim::about(
            OBFUSCATED_INTO_SILENCE,
            silent_bytes_out > 0 && !silent_dial_plain && silent_bytes_back == 0,
            Evidence::Captured,
            format!(
                "rmule's first dial to {silent}: {silent_bytes_out} bytes out, opening plain \
                 {silent_dial_plain}; {silent_bytes_back} bytes back"
            ),
        ),
        Claim::about(
            CRYPT_UNANSWERED,
            first_cause == "crypt_unanswered"
                && (rows.silent_dial_secs - CRYPT_TIMEOUT_SECS).abs() <= CRYPT_TIMEOUT_SLACK_SECS,
            Evidence::RmuleOnly,
            format!(
                "first download.dial_ended for {silent}: cause {first_cause}, {:.1} s after \
                 rmule's SYN on the tap ({} SYNs in all; causes {:?})",
                rows.silent_dial_secs, rows.silent_dials, rows.silent_dial_causes
            ),
        ),
        Claim::about(
            LIVE_CRYPT,
            !live_dial_plain && live_bytes_back > 0 && rows.copies_equal == [true, true],
            Evidence::Captured,
            format!(
                "rmule's first dial to {live} opening plain {live_dial_plain}, {live_bytes_back} \
                 bytes back; copies byte-equal {:?}",
                rows.copies_equal
            ),
        ),
    ];
    let (verdict, detail) = label(&claims);
    let text = toml::to_string_pretty(&Verdict {
        flow: "peer-one-link-silent",
        verdict,
        detail,
        rows: &rows,
        claim: &claims,
    })
    .context("serialize the silent verdict")?;
    fs::write(run_dir.join(VERDICT), &text).context("write the silent verdict")?;
    println!("{text}");
    Ok(verdict)
}

#[cfg(test)]
mod tests {
    use super::dial_ends;

    #[test]
    fn only_the_silent_peers_dial_ends_are_read_with_their_causes() {
        let log = "download.dial_ended id=1 cause=crypt_unanswered peer=172.18.0.4:4662 at_unix_ms=41500\n\
                   download.dial_ended id=2 cause=reset peer=172.18.0.3:4662 at_unix_ms=2000\n\
                   download.dial_ended id=2 cause=crypt_unanswered peer=172.18.0.4:46620 at_unix_ms=3000\n";
        let peer = "172.18.0.4:4662".parse().unwrap();
        assert_eq!(
            dial_ends(log, peer),
            [("crypt_unanswered".to_owned(), 41.5)]
        );
    }
}
