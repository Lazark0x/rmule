//! Rung 0 of a download's Low-ID route: a Low-ID candidate's
//! IPv6 half is dialed first while we hold a Known IPv6, and a dial that never
//! connects hands the candidate to the callback roads, once.

use rmule_primitives::{
    CryptStance, ExchangedSource, Ipv6Endpoint, OutboundCrypt, PeerSource, SourceCryptOptions,
    UserHash,
};

use super::*;

fn half() -> Ipv6Endpoint {
    Ipv6Endpoint::new("3fff:ed2:1::7".parse().unwrap(), 4662)
}

/// The same source's IPv6 half after it moved (a new prefix, a privacy
/// address rotation).
fn moved_half() -> Ipv6Endpoint {
    Ipv6Endpoint::new("3fff:ed2:2::7".parse().unwrap(), 4662)
}

const TARGET_HASH: UserHash = UserHash::from_bytes([0x5A; UserHash::BYTE_LEN]);

/// An ExtSX Low-ID record at `half` whose crypt byte is `crypt` and which
/// carried the target's User Hash, as a v≥2 answer does.
fn low_with_crypt(n: u32, half: Ipv6Endpoint, crypt: u8) -> LowIdCandidate {
    LowIdCandidate::from_source(
        ExchangedSource::new(
            PeerSource::new(low(n), 4662),
            Some(TARGET_HASH),
            Some(SourceCryptOptions::from_byte(crypt)),
        )
        .with_ipv6_half(Some(half)),
        None,
    )
    .expect("a Low-ID source is a candidate")
}

fn known_ipv6() -> DialPosition {
    DialPosition {
        known_ipv6: Some("3fff:ed2:1::2".parse().unwrap()),
    }
}

/// An ExtSX Low-ID record with a `CT_MOD_IP_V6` half, as the
/// connected-server namespace pools it.
fn low_with_half(n: u32) -> ConnectedServerCandidate {
    LowIdCandidate::from_connected_server(
        ExchangedSource::plain(PeerSource::new(low(n), 4662)).with_ipv6_half(Some(half())),
    )
    .expect("a Low-ID source is a candidate")
}

fn state(capability: CallbackCapability, dial: DialPosition) -> DownloadState {
    state_with(vec![low_with_half(7)], capability, dial)
}

fn state_with(
    low_id: Vec<ConnectedServerCandidate>,
    capability: CallbackCapability,
    dial: DialPosition,
) -> DownloadState {
    DownloadState::new(
        DownloadId::from_u64(1),
        file_hash_only_content(ONE_PART),
        StartingCandidates {
            high_id: Vec::new(),
            peer_crypts: HashMap::new(),
            low_id,
            distrusted: HashSet::new(),
            remembered: RememberedSeeds::default(),
        },
        SourcingPosture {
            callback_capability: capability,
            dial,
            ..QUIET_POSTURE
        },
        CALLBACK_TIMEOUT,
        1,
    )
}

fn requested_callback(decisions: &[Decision]) -> bool {
    decisions
        .iter()
        .any(|d| matches!(d, Decision::RequestCallback { low_id } if *low_id == low(7)))
}

#[test]
fn a_low_id_candidate_with_an_ipv6_half_is_dialled_there_before_any_callback() {
    let mut state = state(CallbackCapability::server_high_id(), known_ipv6());
    let decisions = state.start();
    assert_eq!(spawned(&decisions), vec![PeerEndpoint::V6(half())]);
    assert!(
        decisions.iter().any(|d| matches!(
            d,
            Decision::Emit(DownloadEvent::PeerSelected { peer, .. }) if *peer == PeerEndpoint::V6(half())
        )),
        "the rung-0 dial is recorded as any selected peer is: {decisions:?}"
    );
    assert!(
        !requested_callback(&decisions),
        "no callback while the IPv6 dial is open: {decisions:?}"
    );
}

/// The v6 dial fails before connecting: the candidate falls to the server
/// callback on the freed slot, and when that lapses too its half is not dialed
/// a second time.
#[test]
fn a_failed_ipv6_dial_falls_to_the_callback_road_once() {
    let mut state = state(CallbackCapability::server_high_id(), known_ipv6());
    let _ = state.start();

    let fell = state.on_worker_event(PeerEndpoint::V6(half()), PeerWorkerEvent::Disconnected);
    assert!(
        requested_callback(&fell),
        "the callback road follows: {fell:?}"
    );
    assert!(spawned(&fell).is_empty(), "no second IPv6 dial: {fell:?}");

    let lapsed = state.on_callback_timeout(connected_key(low(7)));
    assert!(
        spawned(&lapsed).is_empty() && !requested_callback(&lapsed),
        "a spent half is not re-dialed, and a lapsed callback is not re-asked: {lapsed:?}"
    );
}

/// A dial that connected reached the peer: its later end is an ordinary
/// worker's, and no callback is asked of a peer we already spoke to.
#[test]
fn a_connected_ipv6_dial_does_not_fall_to_a_callback() {
    let mut state = state(CallbackCapability::server_high_id(), known_ipv6());
    let _ = state.start();
    let _ = state.on_worker_event(PeerEndpoint::V6(half()), PeerWorkerEvent::Connected);
    let ended = state.on_worker_event(PeerEndpoint::V6(half()), PeerWorkerEvent::Disconnected);
    assert!(!requested_callback(&ended), "{ended:?}");
}

/// Without a Known IPv6 of ours the AND fails and rung 0 is skipped: the
/// candidate takes its callback road at once.
#[test]
fn without_a_known_ipv6_rung_0_is_skipped() {
    let mut state = state(
        CallbackCapability::server_high_id(),
        DialPosition::default(),
    );
    let decisions = state.start();
    assert!(requested_callback(&decisions), "{decisions:?}");
    assert!(spawned(&decisions).is_empty(), "{decisions:?}");
}

/// An uncallable downloader, and a global candidate no coordinator of ours can
/// introduce: its half is its only road. It starves while we hold no IPv6, is
/// admitted the moment one becomes Known, and when that dial fails the
/// starvation is honest — no road is invented after it.
#[test]
fn a_half_is_the_only_road_left_and_its_failure_is_honest_starvation() {
    let mut state = DownloadState::new(
        DownloadId::from_u64(1),
        file_hash_only_content(ONE_PART),
        high_id_candidates(Vec::new()),
        QUIET_POSTURE,
        CALLBACK_TIMEOUT,
        1,
    );
    state.admit_low_id(LowIdCandidate {
        ipv6: Some(half()),
        ..LowIdCandidate::from_source(
            ExchangedSource::plain(PeerSource::new(low(7), 4662)),
            Some(source_server(3)),
        )
        .expect("a Low-ID source is a candidate")
    });
    assert!(state.start().is_empty(), "no route while we hold no IPv6");

    let admitted = state.on_dial_position(known_ipv6());
    assert_eq!(spawned(&admitted), vec![PeerEndpoint::V6(half())]);

    let fell = state.on_worker_event(PeerEndpoint::V6(half()), PeerWorkerEvent::Disconnected);
    assert!(spawned(&fell).is_empty(), "{fell:?}");
    assert!(
        matches!(
            fell.last(),
            Some(Decision::Fail(DownloadFailure::NoUsableSources))
        ),
        "{fell:?}"
    );
}

/// A rung-0 dial is briefed with the crypt side the candidate's record stated
/// — its whole stance, not just the support bit — so the dial meets it with
/// our policy by the High-ID rule: a candidate that
/// requires obfuscation is dialed obfuscated toward its hash even under a
/// policy that only supports it.
#[test]
fn a_rung_0_dial_meets_the_candidates_stated_crypt_side_by_the_high_id_rule() {
    let mut state = state_with(
        vec![ConnectedServerCandidate::from_record(low_with_crypt(
            7,
            half(),
            0x07,
        ))],
        CallbackCapability::server_high_id(),
        known_ipv6(),
    );
    let decisions = state.start();
    assert_eq!(spawned(&decisions), vec![PeerEndpoint::V6(half())]);
    assert_eq!(
        state
            .peer_crypt(PeerEndpoint::V6(half()))
            .outbound(CryptStance::new(true, false, false)),
        OutboundCrypt::Obfuscated {
            toward: TARGET_HASH,
        }
    );
}

/// A User Hash alone keys nothing: a candidate whose crypt byte does not
/// state support is dialed at its half in plaintext, whatever we request.
#[test]
fn a_candidate_without_crypt_support_is_dialled_at_its_half_in_plaintext() {
    let mut state = state_with(
        vec![ConnectedServerCandidate::from_record(low_with_crypt(
            7,
            half(),
            0x00,
        ))],
        CallbackCapability::server_high_id(),
        known_ipv6(),
    );
    let decisions = state.start();
    assert_eq!(spawned(&decisions), vec![PeerEndpoint::V6(half())]);
    assert_eq!(
        state
            .peer_crypt(PeerEndpoint::V6(half()))
            .outbound(CryptStance::new(true, true, false)),
        OutboundCrypt::Plaintext
    );
}

/// A rung-0 dial refused for incompatible crypt stances retires
/// the source for that reason — not as a dead dial — and its candidate does
/// not fall to the callback roads, which meet the same two stances: aMule
/// deletes the client outright.
#[test]
fn a_crypt_incompatible_rung_0_dial_retires_the_candidate_off_every_road() {
    let mut state = state_with(
        vec![ConnectedServerCandidate::from_record(low_with_crypt(
            7,
            half(),
            0x07,
        ))],
        CallbackCapability::server_high_id(),
        known_ipv6(),
    );
    let _ = state.start();

    let refused =
        state.on_worker_event(PeerEndpoint::V6(half()), PeerWorkerEvent::CryptIncompatible);
    assert!(
        refused.iter().any(|d| matches!(
            d,
            Decision::Phase {
                phase: WorkerPhase::Retired {
                    reason: PeerRetirementReason::CryptIncompatible
                },
                ..
            }
        )),
        "the source is retired as crypt-incompatible: {refused:?}"
    );
    assert!(
        !requested_callback(&refused) && spawned(&refused).is_empty(),
        "no callback road and no second dial follow: {refused:?}"
    );
    assert!(
        matches!(
            refused.last(),
            Some(Decision::Fail(DownloadFailure::NoUsableSources))
        ),
        "nothing is left to reach: {refused:?}"
    );
}

/// A download whose one Low-ID candidate (at [`half`]) was dialed first,
/// beside a connected High-ID worker that source-exchanges — so a sighting can
/// arrive while that candidate is on any of its roads.
fn exchanging_state() -> (DownloadState, PeerEndpoint) {
    let high = peer(1);
    let mut state = DownloadState::new(
        DownloadId::from_u64(1),
        file_hash_only_content(ONE_PART),
        StartingCandidates {
            high_id: vec![high],
            peer_crypts: HashMap::new(),
            low_id: vec![low_with_half(7)],
            distrusted: HashSet::new(),
            remembered: RememberedSeeds::default(),
        },
        SourcingPosture {
            callback_capability: CallbackCapability::server_high_id(),
            dial: known_ipv6(),
            ..QUIET_POSTURE
        },
        CALLBACK_TIMEOUT,
        2,
    );
    let started = state.start();
    assert!(
        spawned(&started).contains(&PeerEndpoint::V6(half())),
        "{started:?}"
    );
    let _ = state.on_worker_event(high, PeerWorkerEvent::Connected);
    (state, high)
}

/// `high`'s source exchange names the candidate at `at`; what it spawned.
fn sight(state: &mut DownloadState, high: PeerEndpoint, at: Ipv6Endpoint) -> Vec<PeerEndpoint> {
    let source = ExchangedSource::plain(PeerSource::new(low(7), 4662)).with_ipv6_half(Some(at));
    let decisions = state.on_worker_event(
        high,
        PeerWorkerEvent::SourcesReceived {
            sources: vec![source],
        },
    );
    spawned(&decisions)
}

/// The dial at `dialed` fails; the candidate falls to its callback road.
fn fail_dial(state: &mut DownloadState, dialed: Ipv6Endpoint) {
    let fell = state.on_worker_event(PeerEndpoint::V6(dialed), PeerWorkerEvent::Disconnected);
    assert!(requested_callback(&fell), "{fell:?}");
}

/// The spent mark is the half's, not the candidate's. After a
/// failed dial the candidate takes its other road; once that lapses, a later
/// sighting at the same half does not dial it again, while one at a new half
/// re-opens rung 0 there — once, since that half is spent in turn.
#[test]
fn a_new_half_reopens_rung_0_once_and_a_spent_half_stays_spent() {
    let (mut state, high) = exchanging_state();
    // A dial at `dialed` fails and the callback road it fell to lapses, so
    // the next sighting is admitted afresh.
    let fail_and_lapse = |state: &mut DownloadState, dialed: Ipv6Endpoint| {
        fail_dial(state, dialed);
        let _ = state.on_callback_timeout(connected_key(low(7)));
    };

    fail_and_lapse(&mut state, half());
    let same = sight(&mut state, high, half());
    assert!(same.is_empty(), "a spent half is not re-dialed: {same:?}");

    // That sighting took the callback road; let it lapse too.
    let _ = state.on_callback_timeout(connected_key(low(7)));
    let moved = sight(&mut state, high, moved_half());
    assert_eq!(moved, vec![PeerEndpoint::V6(moved_half())]);

    fail_and_lapse(&mut state, moved_half());
    let again = sight(&mut state, high, moved_half());
    assert!(again.is_empty(), "the new half is spent in turn: {again:?}");
}

/// A spent rung-0 half is spent for one to two re-ask periods, like any
/// High-ID endpoint, not for the run: once it has sat one out,
/// the next sighting dials it again.
#[test]
fn a_spent_half_is_redialled_after_it_sits_out_a_reask_period() {
    let (mut state, high) = exchanging_state();
    fail_dial(&mut state, half());
    let _ = state.on_callback_timeout(connected_key(low(7)));

    state.on_reask_period();
    let _ = state.on_callback_timeout(connected_key(low(7)));
    let within = sight(&mut state, high, half());
    assert!(
        within.is_empty(),
        "spent in the period that just ended: {within:?}"
    );
    let _ = state.on_callback_timeout(connected_key(low(7)));

    state.on_reask_period();
    assert_eq!(
        sight(&mut state, high, half()),
        vec![PeerEndpoint::V6(half())]
    );
}

/// A new half named while the candidate's callback is pending is kept, not
/// dropped: the pending road runs on undisturbed, and when it
/// lapses the candidate is dialed at that half before any second callback —
/// whose own failure then falls to the callback road once more.
#[test]
fn a_half_sighted_while_a_callback_is_pending_is_dialled_when_the_callback_lapses() {
    let (mut state, high) = exchanging_state();
    fail_dial(&mut state, half());

    let during = sight(&mut state, high, moved_half());
    assert!(
        during.is_empty(),
        "the pending callback is not preempted: {during:?}"
    );

    let lapsed = state.on_callback_timeout(connected_key(low(7)));
    assert_eq!(spawned(&lapsed), vec![PeerEndpoint::V6(moved_half())]);
    assert!(!requested_callback(&lapsed), "{lapsed:?}");

    fail_dial(&mut state, moved_half());
}

/// The spent half is the one road choice's to judge, however it is heard of:
/// seen again while the callback it fell to is pending, it opens nothing when
/// that callback lapses.
#[test]
fn a_spent_half_sighted_while_a_callback_is_pending_stays_spent() {
    let (mut state, high) = exchanging_state();
    fail_dial(&mut state, half());

    let during = sight(&mut state, high, half());
    assert!(during.is_empty(), "{during:?}");

    let lapsed = state.on_callback_timeout(connected_key(low(7)));
    assert!(
        spawned(&lapsed).is_empty() && !requested_callback(&lapsed),
        "a lapsed road with only a spent half ends the candidate: {lapsed:?}"
    );
}

/// The IP filter judges a Low ID's rung-0 half at ingest, by the rule every
/// dialable half meets: a refused half is dropped from the record on
/// either channel, so the route choice never sees it and the candidate takes
/// its callback road at once.
#[test]
fn an_ip_filtered_rung_0_half_never_reaches_the_route_choice() {
    use crate::dialable::{admit_exchanged_halves, admit_kad_halves};
    let admits = |endpoint| endpoint != PeerEndpoint::V6(half());
    let capability = CallbackCapability::server_high_id();

    let exchanged = admit_exchanged_halves(
        ExchangedSource::plain(PeerSource::new(low(7), 4662)).with_ipv6_half(Some(half())),
        admits,
    )
    .expect("a Low ID names no address of its own to refuse");
    let candidate =
        LowIdCandidate::from_source(exchanged, None).expect("a Low-ID source is a candidate");
    assert_eq!(
        LowIdRoute::of(&capability, known_ipv6(), &candidate),
        Some(LowIdRoute::Road(LowIdRoad::Callback))
    );

    let row = admit_kad_halves(
        crate::KadSource {
            ipv6: Some(half()),
            ..super::sources::kad_buddy_row(0)
        },
        admits,
    )
    .expect("a buddy row names no address of its own to refuse");
    let candidate = LowIdCandidate::from_kad_row(&row).expect("a buddy row is a candidate");
    assert_eq!(
        LowIdRoute::of(&capability, known_ipv6(), &candidate),
        Some(LowIdRoute::Road(LowIdRoad::BuddyCallback))
    );
}
