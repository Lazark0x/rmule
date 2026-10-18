//! The upload preference (ADR-0116): a waiter at whose queue one of our
//! downloads stands ranks by the **Reciprocity Factor** — only under both its
//! address and its User Hash, and only within the factor, so a waiter that
//! has waited long enough longer still passes it.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rmule_primitives::{FileHash, Ipv4Endpoint, PeerEndpoint, UserHash};

use super::super::current_modifiers;
use crate::credit::SharedCreditStore;
use crate::held_places::{HeldPlace, RECIPROCITY_FACTOR, SharedHeldPlaces};
use crate::hello_facts::HelloFacts;
use crate::service::DownloadId;
use crate::store::credit::DurableCreditStore;
use crate::upload_queue::UploadSlotQueue;

fn at(octet: u8) -> PeerEndpoint {
    PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, octet), 4662))
}

fn hash(n: u8) -> UserHash {
    UserHash::from_bytes([n; 16])
}

const FILE: FileHash = FileHash::from_bytes([3; 16]);

/// The score modifiers of `peers` — each an endpoint and the User Hash its
/// hello named — with one download standing queued at peer `held`.
async fn modifiers(
    peers: &[(PeerEndpoint, UserHash)],
    held: (PeerEndpoint, UserHash),
) -> HashMap<PeerEndpoint, f64> {
    let credit: SharedCreditStore =
        Arc::new(DurableCreditStore::new(rmule_testkit::memory_store()));
    let places = SharedHeldPlaces::default();
    let seat = places.seat(DownloadId::from_u64(1));
    seat.hold([HeldPlace {
        user_hash: held.1,
        ip: held.0.ip(),
    }]);
    let identities = peers
        .iter()
        .map(|&(peer, user_hash)| (peer, HelloFacts::of(user_hash).identity()))
        .collect();
    current_modifiers(&credit, &places, &identities).await
}

/// A held place's waiter scores by the factor; a waiter that only claims its
/// hash from another address, or stands at no held place, scores by its
/// credit alone.
#[tokio::test]
async fn a_held_place_scores_by_the_factor_only_under_its_address_and_hash() {
    let peers = [(at(1), hash(1)), (at(2), hash(2)), (at(3), hash(1))];
    let modifiers = modifiers(&peers, (at(1), hash(1))).await;
    assert_eq!(modifiers[&at(1)], RECIPROCITY_FACTOR);
    assert_eq!(modifiers[&at(2)], 1.0);
    assert_eq!(
        modifiers[&at(3)],
        1.0,
        "a hash claimed from elsewhere earns nothing"
    );
}

/// Who takes the slot a holder frees `waited` after a waiter we queue at
/// joined, when another joined `head_start` before it.
async fn promoted(head_start: Duration, waited: Duration) -> PeerEndpoint {
    let t0 = Instant::now();
    let modifiers = modifiers(&[(at(1), hash(1)), (at(2), hash(2))], (at(1), hash(1))).await;
    let mut queue = UploadSlotQueue::new(1, 8);
    let _ = queue.admit(at(9), FILE, t0);
    let _ = queue.admit(at(2), FILE, t0);
    let _ = queue.admit(at(1), FILE, t0 + head_start);
    let freed = queue.release(at(9), t0 + head_start + waited, &modifiers);
    freed.granted.expect("a waiter takes the slot").0
}

/// The preference stays inside aMule's score: a waiter we queue at passes
/// one that waited up to 18/7 as long, and no further.
#[tokio::test]
async fn a_waiter_we_queue_at_passes_another_only_within_the_factor() {
    let waited = Duration::from_secs(100);
    assert_eq!(promoted(Duration::from_secs(100), waited).await, at(1));
    assert_eq!(promoted(Duration::from_secs(200), waited).await, at(2));
}
