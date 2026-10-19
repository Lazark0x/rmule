//! Who holds a peer's standing and on which clock the next holder asks
//! (ADR-0107 invariants 12 and 14).

use std::net::Ipv4Addr;

use rmule_primitives::{Ipv4Endpoint, PeerEndpoint};

use super::*;

fn peer() -> AskName {
    AskName::Endpoint(PeerEndpoint::V4(Ipv4Endpoint::new(
        Ipv4Addr::new(10, 0, 0, 1),
        4662,
    )))
}

fn place(asked: Option<Instant>, needs_parts: bool) -> Place {
    Place {
        names: vec![peer()],
        asked,
        needs_parts,
    }
}

fn seat(standings: &SharedQueueStandings, id: u64) -> StandingSeat {
    StandingSeat::new(Arc::clone(standings), DownloadId::from_u64(id))
}

/// The peer's entry names the file the last slot ask asked for, so that
/// download holds and the earlier one waits; a holder holding no part we need
/// yields, and the download that takes over pings nothing — the peer still
/// holds the other file — and asks by TCP on the peer's clock.
#[test]
fn the_last_slot_ask_holds_and_a_holder_needing_nothing_yields() {
    let t0 = Instant::now();
    let later = t0 + Duration::from_secs(10);
    let standings = QueueStandings::shared();
    let (first, second) = (seat(&standings, 1), seat(&standings, 2));
    first.publish(vec![place(Some(t0), true)]);
    second.publish(vec![place(Some(later), true)]);
    assert_eq!(
        first.role(&place(Some(t0), true)),
        Role::Waits {
            asked_at: Some(later)
        }
    );
    assert_eq!(second.role(&place(Some(later), true)), Role::Holds);

    second.publish(vec![place(Some(later), false)]);
    assert_eq!(
        first.role(&place(Some(t0), true)),
        Role::Inherits { asked_at: later }
    );
    assert!(matches!(
        second.role(&place(Some(later), false)),
        Role::Waits { .. }
    ));
}

/// The holder's last ask outlives its place: a waiter left alone when the
/// holder's run ends asks a period after that ask, not after its own.
#[test]
fn the_peer_clock_outlives_the_holder_that_stamped_it() {
    let t0 = Instant::now();
    let full_ask = t0 + Duration::from_secs(1_300);
    let standings = QueueStandings::shared();
    let holder = seat(&standings, 1);
    let waiter = seat(&standings, 2);
    holder.publish(vec![place(Some(t0), true)]);
    waiter.publish(vec![place(None, true)]);
    holder.stamp(&[peer()], full_ask);
    drop(holder);
    assert_eq!(
        waiter.role(&place(None, true)),
        Role::Inherits { asked_at: full_ask }
    );
}
