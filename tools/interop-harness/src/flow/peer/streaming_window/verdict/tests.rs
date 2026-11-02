//! The claims a topology draws, over hand-built statuses and requests.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use rmule_primitives::ED2K_PART_SIZE;

use super::super::replay::Replay;
use super::super::wire::{Request, Status, StatusForm, Wire};
use super::{SeedRow, TopologyFile, advertised, advertised_only, claims};

const SEED: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

fn set(parts: &[u32]) -> BTreeSet<u32> {
    parts.iter().copied().collect()
}

fn request(at: f64, parts: &[u32]) -> Request {
    Request {
        at,
        seed: SEED,
        parts: set(parts),
    }
}

/// A request is judged by the statuses the seed sent before it: a part it
/// never advertised, or any part asked before its status, is a violation.
#[test]
fn a_request_outside_the_seeds_status_is_a_violation() {
    let status = Status {
        at: 2.0,
        seed: SEED,
        count: 4,
        form: StatusForm::Counted { phantom: false },
        held: set(&[0, 2]),
    };
    let mut wire = Wire {
        statuses: vec![status],
        requests: vec![request(3.0, &[0]), request(4.0, &[2])],
        ..Wire::default()
    };
    assert_eq!(advertised_only(&wire, &advertised(&wire)).outcome, "held");

    wire.requests.push(request(5.0, &[1]));
    assert_eq!(advertised_only(&wire, &advertised(&wire)).outcome, "absent");
    wire.requests = vec![request(1.0, &[0])];
    assert_eq!(advertised_only(&wire, &advertised(&wire)).outcome, "absent");
}

/// A one-part file's seeds send no status, because aMule asks none for it;
/// the claims read off a status are not drawn, the rest still are.
#[test]
fn a_one_part_file_draws_no_claim_read_off_a_status() {
    let topology = TopologyFile {
        file_size: ED2K_PART_SIZE,
        file_hash: "00".repeat(16),
        window_parts: 0,
        max_connections: 0,
        rmule_ip: Ipv4Addr::new(10, 0, 0, 1),
        seeds: vec![SeedRow {
            role: "a".to_owned(),
            ip: SEED,
            holding: "complete".to_owned(),
            container: String::new(),
            max_upload_kib: 200,
        }],
        expect_complete: true,
        rmule_container: String::new(),
        tap_container: String::new(),
        seed_netem_delay_ms: None,
        corrupt: None,
    };
    let drawn = claims(
        &topology,
        &Wire::default(),
        &BTreeMap::new(),
        &Replay::default(),
    );
    let outcome = |name: &str| {
        drawn
            .iter()
            .find(|claim| claim.name == name)
            .map(|claim| claim.outcome)
    };
    for name in [
        "every-request-names-a-part-the-seed-advertised",
        "each-seed-is-first-asked-for-a-very-rare-part-else-a-band-part",
        "every-part-handed-out-is-the-rank-minimum",
    ] {
        assert_eq!(outcome(name), Some("blocked"), "{name}");
    }
    assert_eq!(outcome("a-complete-seeds-count-0-status-decodes"), None);
    assert_eq!(outcome("the-download-completed"), Some("absent"));
}
