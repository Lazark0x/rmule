//! The claims against hand-laid runs: each reads what a rule would break.

use std::net::{Ipv4Addr, SocketAddr};

use super::super::marks::Trail;
use super::super::wire::{Item, Said, Status, Wire};
use super::{Body, Claim, Knobs, Run, STRADDLE, Stimulus, TopologyFile, Verdict, claims};
use crate::flow::ed2k_server::search_wire::server_tap::OfferedRow;

const STREAM: [u8; 16] = [0x11; 16];
const WHOLE: [u8; 16] = [0x22; 16];
const DOWNLOADER: Ipv4Addr = Ipv4Addr::new(172, 19, 0, 7);
const STIMULUS: Ipv4Addr = Ipv4Addr::new(172, 19, 0, 9);

/// Owns what a [`Run`] borrows.
struct Fixture {
    topology: TopologyFile,
    wire: Wire,
    trail: Trail,
    offers: Vec<(f64, Vec<OfferedRow>)>,
    stream: Vec<u8>,
}

impl Fixture {
    /// A six-part file, one downloader, rmule's trail `stdout`.
    fn new(stdout: &str) -> Self {
        Self {
            topology: TopologyFile {
                file_name: "stream.mkv".to_owned(),
                file_size: 52_640_000,
                file_hash: "11".repeat(16),
                part_hashes: Vec::new(),
                whole_size: 0,
                whole_hash: None,
                rmule_ip: Ipv4Addr::new(172, 19, 0, 5),
                rmule_container: String::new(),
                tap_container: String::new(),
                seeds: Vec::new(),
                downloaders: vec![Body {
                    role: "downloader".to_owned(),
                    ip: DOWNLOADER,
                    container: String::new(),
                    detail: String::new(),
                }],
                stimuli: Vec::new(),
                actions: Vec::new(),
                knobs: Knobs {
                    prober: false,
                    queued: false,
                    pause: false,
                    restart: false,
                    straddle: true,
                    dial_downloaders: false,
                    rmule_server: "lugdunum".to_owned(),
                    downloader_image: String::new(),
                },
            },
            wire: Wire::default(),
            trail: Trail::new(stdout),
            offers: Vec::new(),
            stream: vec![7; 52_640_000],
        }
    }

    fn item(&mut self, at: f64, peer: Ipv4Addr, from_rmule: bool, said: Said) {
        self.wire.items.push(Item {
            at,
            peer: SocketAddr::new(peer.into(), 40_000),
            from_rmule,
            said,
        });
    }

    fn claim(&self, name: &str) -> Claim {
        let run = Run {
            topology: &self.topology,
            wire: &self.wire,
            trail: &self.trail,
            offers: &self.offers,
            flags: Some(0x0000_17F9),
            stream: &self.stream,
            whole: None,
            stream_hash: STREAM,
            whole_hash: self.topology.whole_hash.as_ref().map(|_| WHOLE),
            part_hashes: Vec::new(),
            count: 6,
        };
        claims(&run)
            .into_iter()
            .find(|claim| claim.name == name)
            .expect("the claim is scored")
    }
}

/// Parts 0 and 3 verified from 1000 s on.
const TRAIL: &str = "\
download parts_tick id=1 at_unix_ms=999000 parts=MMMMMM
download parts_tick id=1 at_unix_ms=1000000 parts=VMMVMM
download parts_tick id=1 at_unix_ms=1010000 parts=VMMVMM
";

fn status(held: &[u32]) -> Said {
    Said::Status {
        hash: STREAM,
        status: Status {
            count: 6,
            held: held.iter().copied().collect(),
        },
    }
}

/// A status naming the verified parts passes; one naming a part rmule has
/// not verified fails, and so does the complete form for a partial.
#[test]
fn a_status_must_be_the_verified_range_of_its_moment() {
    const NAME: &str = "every-status-is-the-verified-range";
    let mut exact = Fixture::new(TRAIL);
    exact.item(1005.0, DOWNLOADER, true, status(&[0, 3]));
    assert_eq!(exact.claim(NAME).verdict, Verdict::Pass);

    let mut beyond = Fixture::new(TRAIL);
    beyond.item(1005.0, DOWNLOADER, true, status(&[0, 1, 3]));
    assert_eq!(beyond.claim(NAME).verdict, Verdict::Fail);

    let mut complete = Fixture::new(TRAIL);
    complete.item(
        1005.0,
        DOWNLOADER,
        true,
        Said::Status {
            hash: STREAM,
            status: Status {
                count: 0,
                held: [].into(),
            },
        },
    );
    assert_eq!(complete.claim(NAME).verdict, Verdict::Fail);
}

/// Laid out as the straddle stimulus draws it: granted, the straddling
/// request, then the in-range one.
fn straddled(stdout: &str, block_after: bool) -> Fixture {
    let mut run = Fixture::new(stdout);
    let across = (9_723_904, 9_732_096);
    run.topology.stimuli.push(Stimulus {
        purpose: STRADDLE.to_owned(),
        container: String::new(),
        ip: STIMULUS,
        started_at: 1001.0,
        ended_at: 1046.0,
        ranges: vec![across, (0, 4_096)],
    });
    run.item(1002.0, STIMULUS, true, Said::Accept);
    let request = |ranges| Said::Request {
        hash: STREAM,
        ranges,
    };
    run.item(1003.0, STIMULUS, false, request(vec![across]));
    run.item(1013.0, STIMULUS, false, request(vec![(0, 4_096)]));
    if block_after {
        run.item(
            1013.1,
            STIMULUS,
            true,
            Said::Block {
                hash: STREAM,
                start: 0,
                bytes: vec![7; 4_096],
            },
        );
    }
    run
}

/// Nothing sent after the straddle and the slot released passes; a block
/// for the in-range request after it fails, the slot still held.
#[test]
fn a_straddle_must_end_the_slot_with_nothing_sent() {
    const NAME: &str = "a-straddling-request-ends-the-slot-and-keeps-the-link";
    let released =
        format!("{TRAIL}serve.upload_slot_released peer={STIMULUS}:4662 at_unix_ms=1003010\n");
    assert_eq!(
        straddled(&released, false).claim(NAME).verdict,
        Verdict::Pass
    );
    assert_eq!(
        straddled(&released, true).claim(NAME).verdict,
        Verdict::Fail
    );
    assert_eq!(straddled(TRAIL, false).claim(NAME).verdict, Verdict::Fail);
}

/// Under the compression flag the partial rides `0xFCFCFCFC:0xFCFC` beside
/// the whole file's `0xFBFBFBFB:0xFBFB`; a partial under the complete
/// marker fails.
#[test]
fn the_announce_must_mark_the_partial_incomplete() {
    const NAME: &str = "the-announce-marks-the-partial-incomplete-beside-a-whole-file";
    let row = |hash, client_id, port| OfferedRow {
        hash,
        client_id,
        port,
    };
    let mut marked = Fixture::new(TRAIL);
    marked.topology.whole_hash = Some("22".repeat(16));
    marked.offers.push((
        1001.0,
        vec![
            row(WHOLE, 0xFBFB_FBFB, 0xFBFB),
            row(STREAM, 0xFCFC_FCFC, 0xFCFC),
        ],
    ));
    assert_eq!(marked.claim(NAME).verdict, Verdict::Pass);

    let mut misread = Fixture::new(TRAIL);
    misread
        .offers
        .push((1001.0, vec![row(STREAM, 0xFBFB_FBFB, 0xFBFB)]));
    assert_eq!(misread.claim(NAME).verdict, Verdict::Fail);
}
