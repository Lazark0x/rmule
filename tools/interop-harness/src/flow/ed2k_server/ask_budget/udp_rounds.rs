//! The Server Pace off the tap: rmule's server-UDP datagrams, the spacing
//! between them and the files each asks for. aMule steps one datagram a
//! second and gives one server at most 35 files a round
//! (`DownloadQueue.cpp:868-958`, `MAX_REQUESTS_PER_SERVER`).
//!
//! A datagram sealed under the server's key hides its opcode, but keeps its
//! length: eight bytes of seal over the plain frame
//! (`EncryptedDatagramSocket.cpp:109`, no padding). So the sealed size says
//! how many files it carries.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::Ipv4Addr;

use crate::flow::pcap::Udp4Datagram;

/// eD2k's server protocol byte.
const OP_EDONKEYPROT: u8 = 0xE3;
const OP_GLOBGETSOURCES2: u8 = 0x94;
const OP_GLOBSERVSTATREQ: u8 = 0x96;
const OP_GLOBGETSOURCES: u8 = 0x9A;
/// The eD2k frame's protocol byte and opcode.
const FRAME_HEAD: usize = 2;
/// A file in `0x9A`: its hash.
const BARE_FILE: usize = 16;
/// A file in `0x94`: its hash and its size.
const SIZED_FILE: usize = 20;
/// What the Server-UDP Seal adds to a frame (`CRYPT_HEADER_WITHOUTPADDING`).
const SEAL: usize = 8;
/// aMule's step between datagrams, less a scheduler's slip.
const MIN_GAP_SECS: f64 = 0.9;
/// aMule's `MAX_REQUESTS_PER_SERVER`.
const MAX_FILES_PER_SERVER: usize = 35;

/// What one datagram of rmule's was.
#[derive(Debug, PartialEq, Eq)]
enum Kind {
    /// `0x96`, a status ping.
    Ping,
    /// `0x9A` or `0x94`, carrying this many files.
    Ask(usize),
    /// Sealed, its length read as an ask at this many files. Anything whose
    /// length fits no ask is a sealed ping or description ask.
    Sealed(Option<usize>),
    /// A plain frame of no interest here.
    Other,
}

fn files_in(body: usize) -> Option<usize> {
    [SIZED_FILE, BARE_FILE]
        .into_iter()
        .find(|file| body >= *file && body.is_multiple_of(*file))
        .map(|file| body / file)
}

fn kind(payload: &[u8]) -> Kind {
    let body = payload.len().saturating_sub(FRAME_HEAD);
    match (payload.first(), payload.get(1)) {
        (Some(&OP_EDONKEYPROT), Some(&OP_GLOBSERVSTATREQ)) => Kind::Ping,
        (Some(&OP_EDONKEYPROT), Some(&OP_GLOBGETSOURCES)) => Kind::Ask(body / BARE_FILE),
        (Some(&OP_EDONKEYPROT), Some(&OP_GLOBGETSOURCES2)) => Kind::Ask(body / SIZED_FILE),
        (Some(&OP_EDONKEYPROT), _) => Kind::Other,
        _ => Kind::Sealed(files_in(body.saturating_sub(SEAL))),
    }
}

/// The report: a verdict line, then one line per datagram.
pub(super) fn score(datagrams: &[Udp4Datagram], rmule: Ipv4Addr) -> String {
    let ours: Vec<(&Udp4Datagram, Kind)> = datagrams
        .iter()
        .filter(|datagram| *datagram.source.ip() == rmule)
        .map(|datagram| (datagram, kind(&datagram.payload)))
        .collect();
    let spaced =
        |left: &(&Udp4Datagram, Kind)| matches!(left.1, Kind::Ask(_) | Kind::Sealed(Some(_)));
    let asks: Vec<&(&Udp4Datagram, Kind)> = ours.iter().filter(|left| spaced(left)).collect();
    let min_gap = asks
        .windows(2)
        .map(|pair| pair[1].0.at - pair[0].0.at)
        .min_by(f64::total_cmp);
    let mut per_server: BTreeMap<Ipv4Addr, usize> = BTreeMap::new();
    for (datagram, kind) in &asks {
        if let Kind::Ask(files) | Kind::Sealed(Some(files)) = kind {
            *per_server.entry(*datagram.destination.ip()).or_default() += files;
        }
    }
    let most = per_server.values().copied().max().unwrap_or(0);
    let pass = !asks.is_empty()
        && min_gap.is_none_or(|gap| gap >= MIN_GAP_SECS)
        && most <= MAX_FILES_PER_SERVER;
    let pings = ours.iter().filter(|left| left.1 == Kind::Ping).count();
    let sealed = asks
        .iter()
        .filter(|left| matches!(left.1, Kind::Sealed(_)))
        .count();
    let mut out = format!(
        "udp_rounds={} datagrams={} ask_datagrams={} sealed_asks={sealed} plain_pings={pings} \
         min_gap_secs={} files_to_busiest_server={most}\n",
        if pass { "PASS" } else { "FAIL" },
        ours.len(),
        asks.len(),
        min_gap.map_or_else(|| "none".to_owned(), |gap| format!("{gap:.3}")),
    );
    let start = ours.first().map_or(0.0, |(datagram, _)| datagram.at);
    for (datagram, kind) in &ours {
        let _ = writeln!(
            out,
            "{:.3} {} len={} {kind:?}",
            datagram.at - start,
            datagram.destination,
            datagram.payload.len(),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn datagram(at: f64, payload: Vec<u8>) -> Udp4Datagram {
        Udp4Datagram {
            at,
            source: "203.0.113.71:4672".parse().unwrap(),
            destination: "203.0.113.200:4665".parse().unwrap(),
            payload,
        }
    }

    fn ask(files: usize) -> Vec<u8> {
        let mut payload = vec![OP_EDONKEYPROT, OP_GLOBGETSOURCES2];
        payload.resize(FRAME_HEAD + files * SIZED_FILE, 0);
        payload
    }

    /// A round at the pace passes, and its file count is summed per server.
    #[test]
    fn a_paced_round_under_the_cap_passes() {
        let report = score(
            &[datagram(0.0, ask(31)), datagram(1.0, ask(4))],
            "203.0.113.71".parse().unwrap(),
        );
        assert!(report.starts_with("udp_rounds=PASS"), "{report}");
        assert!(report.contains("files_to_busiest_server=35"), "{report}");
    }

    /// Two datagrams inside a second, or a server past 35 files, fail.
    #[test]
    fn a_burst_or_a_server_past_the_cap_fails() {
        let rmule = "203.0.113.71".parse().unwrap();
        let burst = score(&[datagram(0.0, ask(2)), datagram(0.2, ask(2))], rmule);
        assert!(burst.starts_with("udp_rounds=FAIL"), "{burst}");
        let over = score(&[datagram(0.0, ask(31)), datagram(1.0, ask(5))], rmule);
        assert!(over.starts_with("udp_rounds=FAIL"), "{over}");
    }

    /// A sealed datagram's files come out of its length.
    #[test]
    fn a_sealed_ask_is_read_from_its_length() {
        let mut sealed = vec![0x55; FRAME_HEAD + SEAL + 2 * SIZED_FILE];
        sealed[1] = 0x01;
        assert_eq!(kind(&sealed), Kind::Sealed(Some(2)));
    }
}
