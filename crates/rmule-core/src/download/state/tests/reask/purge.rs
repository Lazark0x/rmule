//! The purges aMule makes room with as a file nears its source limit (stock
//! 2.3.3 `PartFile.cpp:1406-1456`): once the file holds 80 % of the default
//! `MaxSourcesPerFile`, one source goes at a time — a Low ID no road reaches
//! 30 s after the last, a no-needed-parts source 40 s after, a queue-full one
//! 60 s after — on one clock per file, the run's start counting as the last.

use super::*;
use crate::download::source_book::{
    LOW_TO_LOW_PURGE_SPACING, NO_NEEDED_PARTS_PURGE_SPACING, QUEUE_FULL_PURGE_SPACING,
    SOURCE_PURGE_AT,
};
use crate::service::{PurgedSource, SourcePurgeReason};

/// A pool of `known` High IDs, `peer(1)` first.
fn pool(known: u32) -> Vec<PeerEndpoint> {
    (1..=known)
        .map(|n| peer(u8::try_from(n).expect("fits a test address")))
        .collect()
}

/// A started download knowing `known` sources, two slots, whose `peer(1)` and
/// `peer(2)` stand queued with a UDP contact and answered their pings with
/// `0x93`, at the instant returned.
fn two_queue_full(known: u32) -> (DownloadState, Instant) {
    let mut state = pooled_state(
        file_hash_only_content(ONE_PART),
        &pool(known),
        live_posture(),
        2,
    );
    let _ = state.start(t0());
    queue_and_hang_up(&mut state, peer(1), true, 5);
    queue_and_hang_up(&mut state, peer(2), true, 6);
    let answered_at = t0() + udp_due();
    assert_eq!(
        pinged(&state.on_tick(answered_at)),
        vec![contact(peer(1)), contact(peer(2))]
    );
    for n in [1, 2] {
        let _ = state.on_reask_reply(answered_at, contact(peer(n)), &queue_full_datagram());
    }
    assert_eq!(state.known_sources(), known);
    (state, answered_at)
}

/// What `decisions` lets go, and why, in order.
fn purged(decisions: &[Decision]) -> Vec<(PurgedSource, SourcePurgeReason)> {
    decisions
        .iter()
        .filter_map(|d| match d {
            Decision::Emit(DownloadEvent::SourcePurged { source, reason, .. }) => {
                Some((*source, *reason))
            }
            _ => None,
        })
        .collect()
}

/// `peer` let go for `reason`.
fn gone(peer: PeerEndpoint, reason: SourcePurgeReason) -> (PurgedSource, SourcePurgeReason) {
    (PurgedSource::Endpoint(peer), reason)
}

/// At the threshold the oldest queue-full source goes at once — the run
/// started minutes ago — and the next a minute later, until the file holds
/// fewer than the threshold.
#[test]
fn a_queue_full_source_is_let_go_once_the_file_nears_its_source_limit() {
    let (mut state, answered_at) = two_queue_full(SOURCE_PURGE_AT + 1);
    assert!(
        state.next_wake().is_some_and(|wake| wake <= answered_at),
        "a purge is already due"
    );

    let first = answered_at + Duration::from_secs(1);
    assert_eq!(
        purged(&state.on_tick(first)),
        vec![gone(peer(1), SourcePurgeReason::QueueFull)],
        "oldest first"
    );
    assert!(!state.remote_queued().any(|at| at == peer(1)));
    assert!(purged(&state.on_tick(first + QUEUE_FULL_PURGE_SPACING / 2)).is_empty());
    assert_eq!(state.next_wake(), Some(first + QUEUE_FULL_PURGE_SPACING));

    let second = first + QUEUE_FULL_PURGE_SPACING;
    assert_eq!(
        purged(&state.on_tick(second)),
        vec![gone(peer(2), SourcePurgeReason::QueueFull)]
    );
    assert_eq!(state.known_sources(), SOURCE_PURGE_AT - 1);
}

/// Below the threshold a queue-full source stays, and its next ping falls due
/// a full reask period after its `0x93`, as a ranked source's would.
#[test]
fn below_the_threshold_a_queue_full_source_keeps_its_standing_and_cadence() {
    let (mut state, answered_at) = two_queue_full(SOURCE_PURGE_AT - 1);

    let later = answered_at + QUEUE_FULL_PURGE_SPACING * 2;
    assert!(purged(&state.on_tick(later)).is_empty());
    assert_eq!(state.remote_queued().count(), 2);
    assert!(pinged(&state.on_tick(answered_at + udp_due() - Duration::from_secs(1))).is_empty());
    assert_eq!(
        pinged(&state.on_tick(answered_at + udp_due())),
        vec![contact(peer(1)), contact(peer(2))]
    );
}

/// A no-needed-parts source is let go 40 s after the last purge once the file
/// holds the threshold (stock 2.3.3 `PartFile.cpp:1423-1436`; no other
/// download takes it over, rmule having no A4AF swap), and kept below it.
#[test]
fn a_no_needed_parts_source_is_let_go_near_the_source_limit() {
    for (known, let_go) in [(SOURCE_PURGE_AT, true), (SOURCE_PURGE_AT - 1, false)] {
        let mut state = pooled_state(
            file_hash_only_content(THREE_PARTS),
            &pool(known),
            live_posture(),
            1,
        );
        let _ = state.start(t0());
        queue_and_hang_up(&mut state, peer(1), true, 5);
        let window = t0() + udp_due();
        let _ = state.on_tick(window);
        let empty = PartBitmap::decode(3, &[0b0000_0000]).expect("three parts");
        let _ = state.on_reask_reply(window, contact(peer(1)), &v4_ack_with(empty, 2));

        let want = if let_go {
            vec![gone(peer(1), SourcePurgeReason::NoNeededParts)]
        } else {
            Vec::new()
        };
        assert_eq!(
            purged(&state.on_tick(window + Duration::from_secs(1))),
            want
        );
    }
}

/// A started download holding `SOURCE_PURGE_AT - 2` High IDs and two Low IDs
/// another server assigned, under `capability`.
fn with_two_global_low_ids(capability: CallbackCapability) -> DownloadState {
    let global = |n| {
        SourceSighting::plain(
            rmule_primitives::PeerSource::new(low(n), 4662),
            rmule_primitives::Informant::Own,
        )
    };
    let mut state = state_from(
        file_hash_only_content(ONE_PART),
        SourcingPosture {
            callback_capability: capability,
            ..live_posture()
        },
        1,
        no_facts(),
        vec![
            (Channel::Server, plain_sightings(&pool(SOURCE_PURGE_AT - 2))),
            (
                Channel::Global(source_server(9)),
                vec![global(7), global(8)],
            ),
        ],
        Vec::new(),
    );
    let _ = state.start(t0());
    assert_eq!(state.known_sources(), SOURCE_PURGE_AT);
    state
}

/// A Low-ID candidate no road reaches while we are connected — we are a Low
/// ID ourselves, so we cannot be called back, and it is another server's, so
/// no coordinator introduces us — is let go 30 s after the last purge once
/// the file holds the threshold (stock 2.3.3 `PartFile.cpp:1406-1418`), named
/// by its low id and the server that assigned it. Offline, no such source is
/// let go: aMule reaches `DS_LOWTOLOWIP` only by asking while connected.
#[test]
fn a_low_id_source_no_road_reaches_is_let_go_near_the_source_limit() {
    let low_id = CallbackCapability::of(
        true,
        Some(crate::own_identity::ConnectedSession {
            server: Some(source_server(1)),
            client_id: low(5),
        }),
        false,
    );
    let mut state = with_two_global_low_ids(low_id);
    assert!(purged(&state.on_tick(t0() + LOW_TO_LOW_PURGE_SPACING / 2)).is_empty());

    let first = t0() + LOW_TO_LOW_PURGE_SPACING;
    assert_eq!(state.next_wake(), Some(first));
    assert_eq!(
        purged(&state.on_tick(first)),
        vec![(
            PurgedSource::LowId {
                low_id: low(7),
                server: Some(source_server(9))
            },
            SourcePurgeReason::LowToLow
        )]
    );
    assert!(
        purged(&state.on_tick(first + LOW_TO_LOW_PURGE_SPACING)).is_empty(),
        "the file is below the threshold"
    );

    let mut offline = with_two_global_low_ids(CallbackCapability::UNCALLABLE);
    assert!(purged(&offline.on_tick(first)).is_empty(), "offline");
}

/// The three purges share one clock (aMule's `lastpurgetime`): after a
/// queue-full source goes, a no-needed-parts one waits 40 s from it, not from
/// its own last purge, and a second queue-full one the full minute.
#[test]
fn the_purges_share_one_clock() {
    let mut state = pooled_state(
        file_hash_only_content(THREE_PARTS),
        &pool(SOURCE_PURGE_AT + 2),
        live_posture(),
        3,
    );
    let _ = state.start(t0());
    for (n, rank) in [(1, 5), (2, 6), (3, 7)] {
        queue_and_hang_up(&mut state, peer(n), true, rank);
    }
    let window = t0() + udp_due();
    let _ = state.on_tick(window);
    let _ = state.on_reask_reply(window, contact(peer(1)), &queue_full_datagram());
    let empty = PartBitmap::decode(3, &[0b0000_0000]).expect("three parts");
    let _ = state.on_reask_reply(window, contact(peer(2)), &v4_ack_with(empty, 2));
    let _ = state.on_reask_reply(window, contact(peer(3)), &queue_full_datagram());

    let first = window + Duration::from_secs(1);
    assert_eq!(
        purged(&state.on_tick(first)),
        vec![gone(peer(1), SourcePurgeReason::QueueFull)],
        "the oldest whose spacing has passed"
    );
    assert!(
        purged(&state.on_tick(first + NO_NEEDED_PARTS_PURGE_SPACING - Duration::from_secs(1)))
            .is_empty()
    );
    assert_eq!(
        purged(&state.on_tick(first + NO_NEEDED_PARTS_PURGE_SPACING)),
        vec![gone(peer(2), SourcePurgeReason::NoNeededParts)]
    );
    let second = first + NO_NEEDED_PARTS_PURGE_SPACING;
    assert!(purged(&state.on_tick(second + QUEUE_FULL_PURGE_SPACING / 2)).is_empty());
    assert_eq!(
        purged(&state.on_tick(second + QUEUE_FULL_PURGE_SPACING)),
        vec![gone(peer(3), SourcePurgeReason::QueueFull)]
    );
}
