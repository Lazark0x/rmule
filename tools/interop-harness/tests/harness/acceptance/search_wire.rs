//! **Search on the wire**: the `search-wire` leg against Lugdunum
//! and ed2k-server. The leg draws no verdict; its reports are the evidence the
//! rulings were made from, so the wrapper reads those reports for the
//! tokenisation findings: how many rows each probe drew from each server, and
//! the terms rmule's multi-word queries put on the wire.

use std::path::Path;

use super::{bench_enabled, read_string, run_flow};

/// What each server does with the tokenisation probes: both
/// match whole words and answer the words of a phrase as separate terms;
/// Lugdunum folds accents and reads a quoted run of words as a word, ed2k-server
/// does neither.
fn tokenisation(server: &str) -> Vec<(&'static str, usize)> {
    let (folds_accents, reads_quoted_words) = match server {
        "lugdunum" => (1, 1),
        "ed2k-server" => (0, 0),
        other => panic!("no tokenisation findings for {other}"),
    };
    vec![
        ("betaga", 0),
        ("alphabet", 0),
        ("gamma", 0),
        ("alphabetagamma", 1),
        ("dashword", 1),
        ("spaceword", 1),
        ("ubuntu desktop", 1),
        ("ubuntu desktop wire", 1),
        ("café", 1),
        ("cafe", folds_accents),
        ("résumé", folds_accents),
        ("\"sepspace spaceword\"", reads_quoted_words),
        ("\"ubuntu desktop\"", 0),
    ]
}

/// The rows the answer to `probe` carried, from the report's
/// `probe[<probe>]: rows=N` line.
fn probe_rows(report: &str, probe: &str) -> Option<usize> {
    let head = format!("probe[{probe}]: rows=");
    report
        .lines()
        .find_map(|line| line.strip_prefix(&head))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|rows| rows.parse().ok())
}

/// Run the leg against one server and check its reports: one server per run
/// keeps a run inside one polling window. `RMULE_BENCH_VERDICT_DIR` scores a
/// retained run instead.
fn search_wire(server: &str, extra: &[&str]) -> std::path::PathBuf {
    // The wrapper runs from the crate directory; the ed2k-server config default
    // is repo-relative.
    let config = Path::new(env!("CARGO_MANIFEST_DIR")).join("images/ed2ksrv/config.toml");
    let config = config.to_str().unwrap().to_string();
    let args: Vec<&str> = [
        "--skip-build",
        "--server",
        server,
        "--ed2ksrv-config",
        &config,
        "--timeout",
        "240",
    ]
    .iter()
    .chain(extra)
    .copied()
    .collect();
    let run_dir = run_flow("search-wire", &args);
    let decoded = read_string(&run_dir, &format!("search-wire/{server}/decoded.txt"));
    for phrase in [
        "SEARCH AND('ubuntu','desktop')",
        "SEARCH AND('ubuntu',AND('desktop','wire'))",
    ] {
        assert!(
            decoded.matches(phrase).count() >= 2,
            "{server}: each requester puts one term per word on the wire, not the phrase as one term ({phrase}):\n{decoded}"
        );
    }
    for requester in ["high-id", "low-id"] {
        let report = read_string(
            &run_dir,
            &format!("search-wire/{server}/{requester}/search-wire.txt"),
        );
        assert!(
            report.contains("login[1]: accepted"),
            "{server} {requester}: the probe logged in:\n{report}"
        );
        for (probe, rows) in tokenisation(server) {
            assert_eq!(
                probe_rows(&report, probe),
                Some(rows),
                "{server} {requester}: rows for probe[{probe}]:\n{report}"
            );
        }
    }
    assert!(
        run_dir
            .join(format!("search-wire/{server}/server.pcap"))
            .exists(),
        "{server}: the server tap wrote its pcap"
    );
    run_dir
}

#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn search_wire_against_lugdunum() {
    if bench_enabled("search-wire lugdunum") {
        let _ = search_wire("lugdunum", &[]);
    }
}

#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn search_wire_against_ed2k_server() {
    if bench_enabled("search-wire ed2k-server") {
        let _ = search_wire("ed2k-server", &[]);
    }
}

/// The more-results walk, beside the leg's own probes. Draws no
/// verdict either — the pcap holds the `0x21` requests and the pages, the
/// report each page's more-results byte — so the wrapper checks the walk ran,
/// and that its pages together carry every row the server holds for the word:
/// all 450 files on Lugdunum, ed2k-server's 200-row cap (`search.rs:19`) there.
/// A walk that comes back short met a sharer still offering its files.
fn search_more(server: &str) {
    let every_row = match server {
        "lugdunum" => 450,
        "ed2k-server" => 200,
        other => panic!("no more-results findings for {other}"),
    };
    let run_dir = search_wire(server, &["--more-results"]);
    for requester in ["high-id", "low-id"] {
        let report = read_string(
            &run_dir,
            &format!("search-wire/{server}/{requester}/search-wire.txt"),
        );
        assert!(
            report.contains("more[morepage] page[0]: rows="),
            "{server} {requester}: the walk's first page was answered:\n{report}"
        );
        let walked: usize = report
            .lines()
            .filter(|line| line.starts_with("more[morepage] page["))
            .filter_map(|line| line.split_once("rows=").map(|(_, rest)| rest))
            .filter_map(|rest| rest.split_whitespace().next()?.parse::<usize>().ok())
            .sum();
        assert_eq!(
            walked, every_row,
            "{server} {requester}: rows over the walk's pages:\n{report}"
        );
    }
}

#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn search_more_against_lugdunum() {
    if bench_enabled("search-wire --more-results lugdunum") {
        search_more("lugdunum");
    }
}

#[test]
#[ignore = "bench flow: requires Docker + RMULE_BENCH=1"]
fn search_more_against_ed2k_server() {
    if bench_enabled("search-wire --more-results ed2k-server") {
        search_more("ed2k-server");
    }
}
