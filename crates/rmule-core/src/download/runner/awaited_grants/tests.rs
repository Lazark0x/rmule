//! The run's Awaited Grants filed from its brain (ADR-0107): a queued
//! source's wait is found by the User Hash its hello named, after the worker
//! that read the hello is gone and from a new address.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use rmule_primitives::{
    FileHash, Informant, Ipv4Endpoint, PeerEndpoint, PeerSource, SourceSighting, UserHash,
};

use super::AwaitedGrants;
use crate::VerificationAuthority;
use crate::adapters::{LinkName, LinkOffer, PeerWorkerEvent, SharedPeerLinks};
use crate::download::source_book::Gate;
use crate::download::state::{
    CallbackCapability, Channel, ContentFacts, DownloadState, SourcingPosture, StartingFacts,
};
use crate::hashing::ResolvedHashSet;
use crate::hello_facts::HelloFacts;
use crate::service::DownloadId;

const SOURCE: UserHash = UserHash::from_bytes([0x5E; UserHash::BYTE_LEN]);

fn at() -> PeerEndpoint {
    PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, 1), 4662))
}

/// A one-part download whose server-sighted source at [`at`] — no crypt, no
/// User Hash on the sighting — queued it at rank 5 under a hello naming
/// [`SOURCE`] and hung up.
fn queued_under_a_hello() -> DownloadState {
    let mut state = DownloadState::new(
        DownloadId::from_u64(1),
        ContentFacts {
            file_hash: FileHash::from_bytes([0; 16]),
            file_size: 1_000,
            link_part_hash_set: None,
            resolved: ResolvedHashSet {
                authority: VerificationAuthority::FileHashOnly,
                hashes: Vec::new(),
            },
            trusted_aich_root: None,
            verified_parts: Vec::new(),
            order: crate::scheduler::PartOrder::Rarest,
        },
        StartingFacts {
            distrusted: std::collections::HashSet::new(),
            seeds_written: 0,
        },
        SourcingPosture {
            callback_capability: CallbackCapability::server_high_id(),
            dial: crate::dialable::DialPosition::default(),
            discovery_active: false,
            client_udp: true,
        },
        Duration::from_secs(30),
        crate::download::connection_budget::BudgetSeat::ceiling(1),
    );
    let now = Instant::now();
    let filter = crate::ip_filter::IpFilter::default();
    let gate = Gate {
        filter: &filter,
        dial: crate::dialable::DialPosition::default(),
    };
    let PeerEndpoint::V4(v4) = at() else {
        unreachable!()
    };
    let sighting = SourceSighting::plain(PeerSource::HighId(v4), Informant::Own);
    let _ = state.on_sightings(now, Channel::Server, [sighting], &gate);
    let _ = state.start(now);
    let _ = state.on_worker_event(now, at(), PeerWorkerEvent::Connected);
    let identity = HelloFacts::of(SOURCE).identity();
    let _ = state.on_worker_event(now, at(), PeerWorkerEvent::Identity(identity));
    let _ = state.on_worker_event(now, at(), PeerWorkerEvent::every_part(1_000));
    let _ = state.on_worker_event(now, at(), PeerWorkerEvent::Queued { rank: 5 });
    let _ = state.on_worker_event(now, at(), PeerWorkerEvent::Disconnected);
    assert_eq!(state.remote_queued().collect::<Vec<_>>(), [at()]);
    state
}

/// The uploader dials back from a new address: its link proves a new endpoint
/// and the same User Hash, and the grant reaches the source waiting at the old
/// one (aMule `FindMatchingClient`, `ClientList.cpp:253-347`).
#[tokio::test]
async fn an_awaited_grant_is_found_by_user_hash_after_the_endpoint_changed() {
    let state = queued_under_a_hello();
    let links = SharedPeerLinks::default();
    let mut awaited = AwaitedGrants::new(links.clone());
    awaited.hold(&state);

    let moved = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, 99), 4662));
    assert!(links.offer_grant(&[LinkName::Endpoint(moved), LinkName::User(SOURCE)]));
    assert_eq!(awaited.next().await, Some(LinkOffer::Grant(at())));
}
