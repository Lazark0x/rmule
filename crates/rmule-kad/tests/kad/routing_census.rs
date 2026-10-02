//! `RoutingCensus` fold behavior: live membership with a retained peak,
//! validated-live counting, and saturation on unmatched evictions.

use std::net::Ipv4Addr;

use rmule_kad::{KadEvent, KadNodeEndpoint, RoutingCensus};
use rmule_testkit::kad_node::id;

fn added(n: u8) -> KadEvent {
    KadEvent::ContactAdded {
        id: id(n),
        endpoint: KadNodeEndpoint::new(Ipv4Addr::new(10, 0, 0, n), 4672),
    }
}

#[test]
fn routing_census_tracks_live_peak_and_liveness() {
    let mut census = RoutingCensus::default();
    census.observe(&added(1));
    census.observe(&added(2));
    census.observe(&KadEvent::ContactResponded { id: id(1) });
    assert_eq!(census.live, 2);
    assert_eq!(census.peak_live, 2);
    assert_eq!(census.responded, 1);

    census.observe(&KadEvent::ContactEvicted { id: id(2) });
    assert_eq!(census.live, 1, "eviction lowers live");
    assert_eq!(census.peak_live, 2, "peak is retained after eviction");
}

#[test]
fn eviction_never_underflows() {
    let mut census = RoutingCensus::default();
    census.observe(&KadEvent::ContactEvicted { id: id(9) });
    assert_eq!(census.live, 0, "an unmatched eviction saturates at zero");
}
