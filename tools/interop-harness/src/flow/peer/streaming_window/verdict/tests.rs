use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use super::super::wire::{Request, Status, StatusForm, Wire};
use super::{advertised, advertised_only};

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
