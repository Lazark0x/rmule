//! The registry driven through its interface, in memory: which download a
//! connection goes to, given how it came in and what its hello says, after
//! each way a registration can be filed, spent, retracted or dropped.

use std::net::Ipv4Addr;
use std::time::Duration;

use rmule_primitives::{Ed2kText, FileHash};
use tokio::time::timeout;

use crate::natt::front::{NattRisenSender, ReportedToFront};

use super::*;

fn hash(byte: u8) -> UserHash {
    UserHash::from_bytes([byte; UserHash::BYTE_LEN])
}

/// A brief whose file names `seed`, so a test can tell which road's brief an
/// adoption carried.
fn brief(seed: u8) -> AdoptionBrief {
    AdoptionBrief {
        file: Ed2kFileLink {
            name: Ed2kText::from_utf8("awaited"),
            size: 4096,
            file_hash: FileHash::from_bytes([seed; FileHash::BYTE_LEN]),
            part_hash_set: None,
            aich_root: None,
            ipv6_sources: Vec::new(),
            sources: Default::default(),
        },
        own_status: PartBitmap::downloader_empty(4096),
        want_sources: true,
    }
}

/// The brain's connected-server key for `low`.
fn callback(low: u32) -> CallbackKey {
    CallbackKey {
        server: None,
        low_id: ClientId::from_u32(low),
    }
}

/// The same key resolved against the connected server, as a called-back
/// peer's hello reports it.
fn routing(low: u32) -> CallbackKey {
    CallbackKey {
        server: Some(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 1), 4661)),
        low_id: ClientId::from_u32(low),
    }
}

/// A key no registration is filed under.
fn nobody() -> CallbackKey {
    routing(0xFFFF)
}

/// One download's two channels.
struct Download {
    adopt_tx: AdoptSender,
    retire_tx: RetireSender,
    retire_rx: mpsc::Receiver<(CallbackKey, AttemptRetirement)>,
}

fn download() -> Download {
    let (retire_tx, retire_rx) = mpsc::channel(4);
    Download {
        adopt_tx: mpsc::channel(4).0,
        retire_tx,
        retire_rx,
    }
}

impl Download {
    fn register(&self, registry: &AwaitedInbound, key: CallbackKey) -> AwaitedInboundHandle {
        registry.register(key, self.adopt_tx.clone(), self.retire_tx.clone())
    }
}

/// The adoption a verdict carries, or a panic naming what came instead.
fn adopted(verdict: InboundVerdict) -> Adoption {
    match verdict {
        InboundVerdict::Adopt(adoption) => adoption,
        InboundVerdict::Mismatch => panic!("a mismatch, not an adoption"),
        InboundVerdict::Unclaimed => panic!("unclaimed, not an adoption"),
    }
}

fn unclaimed(verdict: &InboundVerdict) -> bool {
    matches!(verdict, InboundVerdict::Unclaimed)
}

/// A called-back peer is adopted by the `(server, low id)` its hello reports,
/// handed over under the *brain's* key of the callback, and only once.
#[test]
fn a_called_back_peer_is_adopted_by_the_key_its_hello_reports() {
    let registry = AwaitedInbound::default();
    let first = download();
    let handle = first.register(&registry, callback(7));
    handle.await_callback(routing(7), brief(0x71));

    assert!(unclaimed(&registry.triage(
        InboundArrival::Accepted,
        hash(0x11),
        nobody()
    )));
    let adoption = adopted(registry.triage(InboundArrival::Accepted, hash(0x11), routing(7)));
    assert_eq!(adoption.callback, callback(7));
    assert_eq!(adoption.brief.file.file_hash.as_bytes()[0], 0x71);
    assert!(adoption.adopt_tx.same_channel(&first.adopt_tx));
    assert!(
        unclaimed(&registry.triage(InboundArrival::Accepted, hash(0x11), routing(7))),
        "one callback opens one connection"
    );
}

/// Two roads, one key: whichever road lands first spends both, under the one
/// lock, so the other cannot hand the download a second worker for the slot.
/// A claim the callback's own road outran is let go; one that landed is not.
#[test]
fn whichever_road_lands_first_spends_both() {
    let target = hash(0xAB);
    for tunnel_first in [true, false] {
        let registry = AwaitedInbound::default();
        let diagnostics = DiagnosticsState::default();
        registry.install_diagnostics(diagnostics.clone());
        let waiting = download();
        let handle = waiting.register(&registry, callback(7));
        handle.await_callback(routing(7), brief(0x71));
        handle.claim_tunnel(target, brief(0x72), false);

        let (landed, other) = if tunnel_first {
            (
                registry.triage(InboundArrival::DialedToward(target), target, nobody()),
                registry.triage(InboundArrival::Accepted, target, routing(7)),
            )
        } else {
            (
                registry.triage(InboundArrival::Accepted, target, routing(7)),
                registry.triage(InboundArrival::DialedToward(target), target, nobody()),
            )
        };
        let landed = adopted(landed);
        assert_eq!(landed.callback, callback(7));
        assert_eq!(
            landed.brief.file.file_hash.as_bytes()[0],
            if tunnel_first { 0x72 } else { 0x71 },
            "the worker asks with the brief of the road that landed"
        );
        assert!(unclaimed(&other), "the other road went with it");
        let session = diagnostics.snapshot().session;
        assert_eq!(
            session.natt_download_adoptions_total,
            u64::from(tunnel_first)
        );
        assert_eq!(
            session.natt_download_claims_retired_total,
            u64::from(!tunnel_first)
        );
    }
}

/// Dropping the handle is the callback's end on every road — adopted, lapsed
/// or with its run: both keys are released at once.
#[test]
fn dropping_the_handle_releases_both_keys() {
    let target = hash(0xAB);
    let registry = AwaitedInbound::default();
    let waiting = download();
    let handle = waiting.register(&registry, callback(7));
    handle.await_callback(routing(7), brief(0x71));
    handle.claim_tunnel(target, brief(0x72), true);

    drop(handle);

    assert!(unclaimed(&registry.triage(
        InboundArrival::Accepted,
        target,
        routing(7)
    )));
    assert!(unclaimed(&registry.triage(
        InboundArrival::DialedToward(target),
        target,
        nobody()
    )));
    assert!(registry.is_empty());
}

/// Two downloads wait on one Low-ID peer (ADR-0107): the older takes the
/// first connection, the younger waits for the next, and the older's end
/// cannot take the younger's registration with it.
#[test]
fn two_downloads_on_one_key_are_adopted_oldest_first() {
    let registry = AwaitedInbound::default();
    let (older, younger) = (download(), download());
    let older_handle = older.register(&registry, callback(7));
    older_handle.await_callback(routing(7), brief(0x71));
    let younger_handle = younger.register(&registry, callback(7));
    younger_handle.await_callback(routing(7), brief(0x9E));

    let first = adopted(registry.triage(InboundArrival::Accepted, hash(0x11), routing(7)));
    assert!(first.adopt_tx.same_channel(&older.adopt_tx));
    drop(older_handle);
    let next = adopted(registry.triage(InboundArrival::Accepted, hash(0x11), routing(7)));
    assert!(next.adopt_tx.same_channel(&younger.adopt_tx));
    drop(younger_handle);
    assert!(registry.is_empty());
}

/// Filing a road again keeps its turn. A claim filed again for the same
/// target keeps the dial-back an earlier one stated: the punch beside a buddy
/// callback is a second road to one slot, not a replacement for the first.
#[test]
fn filing_a_road_again_keeps_its_turn_and_its_dial_back() {
    let target = hash(0xAB);
    let registry = AwaitedInbound::default();
    let (older, younger) = (download(), download());
    let older_handle = older.register(&registry, callback(7));
    older_handle.claim_tunnel(target, brief(0x71), true);
    let younger_handle = younger.register(&registry, callback(7));
    younger_handle.claim_tunnel(target, brief(0x9E), true);
    older_handle.claim_tunnel(target, brief(0x72), false);

    let first = adopted(registry.triage(InboundArrival::Accepted, target, nobody()));
    assert!(
        first.adopt_tx.same_channel(&older.adopt_tx),
        "the older claim kept its turn and its dial-back"
    );
    assert_eq!(first.brief.file.file_hash.as_bytes()[0], 0x72);
    drop(younger_handle);
}

/// The hello decides (ADR-0091): a Dialer Tunnel whose peer names somebody
/// else is refused and counted, and every claim on the target stays for the
/// peer that may still come.
#[test]
fn a_stranger_on_a_dialed_tunnel_is_a_mismatch_and_the_claim_stays() {
    let target = hash(0xAB);
    let registry = AwaitedInbound::default();
    let diagnostics = DiagnosticsState::default();
    registry.install_diagnostics(diagnostics.clone());
    let waiting = download();
    let handle = waiting.register(&registry, callback(7));
    handle.claim_tunnel(target, brief(0x71), false);

    assert!(matches!(
        registry.triage(InboundArrival::DialedToward(target), hash(0x11), nobody()),
        InboundVerdict::Mismatch
    ));
    assert_eq!(
        diagnostics
            .snapshot()
            .session
            .natt_download_adoptions_refused_total,
        1
    );
    adopted(registry.triage(InboundArrival::DialedToward(target), target, nobody()));
}

/// A Dialer Tunnel toward a hash nobody claimed is asked about like any
/// accepted connection: its hello's callback key may still be awaited.
#[test]
fn a_dialed_tunnel_nobody_claimed_is_matched_by_its_callback_key() {
    let registry = AwaitedInbound::default();
    let waiting = download();
    let handle = waiting.register(&registry, callback(7));
    handle.await_callback(routing(7), brief(0x71));

    let adoption = adopted(registry.triage(
        InboundArrival::DialedToward(hash(0xAB)),
        hash(0x11),
        routing(7),
    ));
    assert_eq!(adoption.callback, callback(7));
}

/// A path nothing here aimed is adopted by its hello's hash only for a claim
/// that asked the target to dial us back (ADR-0061 route 4); a punch's claim
/// alone leaves it to the serve road (ADR-0091).
#[test]
fn an_accepted_path_is_adopted_by_hash_only_for_a_dial_back_claim() {
    let target = hash(0xAB);
    let registry = AwaitedInbound::default();
    let punch = download();
    let punch_handle = punch.register(&registry, callback(7));
    punch_handle.claim_tunnel(target, brief(0x71), false);
    assert!(unclaimed(&registry.triage(
        InboundArrival::Accepted,
        target,
        nobody()
    )));

    let buddy = download();
    let buddy_handle = buddy.register(&registry, callback(8));
    buddy_handle.claim_tunnel(target, brief(0x9E), true);
    let adoption = adopted(registry.triage(InboundArrival::Accepted, target, nobody()));
    assert!(
        adoption.adopt_tx.same_channel(&buddy.adopt_tx),
        "the oldest claim that asked for a dial-back takes it"
    );
    assert_eq!(adoption.callback, callback(8));
}

/// A retirement reaches every claimant of its target and spends nothing;
/// retracting a claim leaves the callback's own road filed.
#[test]
fn a_retirement_reaches_every_claimant_and_a_retracted_claim_leaves_the_callback() {
    let target = hash(0x5C);
    let registry = AwaitedInbound::default();
    let (mut older, mut younger) = (download(), download());
    let older_handle = older.register(&registry, callback(7));
    older_handle.await_callback(routing(7), brief(0x71));
    older_handle.claim_tunnel(target, brief(0x71), false);
    let younger_handle = younger.register(&registry, callback(8));
    younger_handle.claim_tunnel(target, brief(0x9E), false);

    assert!(registry.retire(target, AttemptRetirement::ServerSilent));
    assert_eq!(
        older.retire_rx.try_recv().map(|(key, _)| key),
        Ok(callback(7))
    );
    assert_eq!(
        younger.retire_rx.try_recv().map(|(key, _)| key),
        Ok(callback(8))
    );

    older_handle.retract_claim();
    let tunnel = adopted(registry.triage(InboundArrival::DialedToward(target), target, nobody()));
    assert!(
        tunnel.adopt_tx.same_channel(&younger.adopt_tx),
        "the retracted claim no longer takes a Tunnel"
    );
    adopted(registry.triage(InboundArrival::Accepted, target, routing(7)));
    assert!(!registry.retire(hash(0x01), AttemptRetirement::ServerSilent));
}

/// Two downloads claim one target: each lets go only of its own claim, and
/// the front hears the attempt abandoned only when the last one does.
#[tokio::test]
async fn the_last_claimant_letting_go_abandons_the_attempt() {
    let target = hash(0xAB);
    let registry = AwaitedInbound::default();
    let (risen, mut reported) = NattRisenSender::test_pair();
    registry.install_risen(risen);
    let (first, second) = (download(), download());
    let first_handle = first.register(&registry, callback(7));
    first_handle.claim_tunnel(target, brief(0x71), false);
    let second_handle = second.register(&registry, callback(8));
    second_handle.claim_tunnel(target, brief(0x9E), false);

    first_handle.retract_claim();
    first_handle.retract_claim();
    drop(first_handle);
    assert!(
        timeout(Duration::from_millis(200), reported.recv())
            .await
            .is_err(),
        "the second download still claims the target"
    );
    drop(second_handle);
    assert_eq!(
        timeout(Duration::from_secs(3), reported.recv())
            .await
            .expect("the front was told within 3s"),
        Some(ReportedToFront::Abandoned(target))
    );
}

/// Every adoption reports the peer its own hello confirmed back to the front,
/// whichever road found it, so that peer's held burst or pending attempt ends.
#[tokio::test]
async fn an_adoption_reports_the_confirmed_hello_to_the_front() {
    let peer = hash(0xAB);
    let registry = AwaitedInbound::default();
    let (risen, mut reported) = NattRisenSender::test_pair();
    registry.install_risen(risen);
    let waiting = download();
    let handle = waiting.register(&registry, callback(7));
    handle.await_callback(routing(7), brief(0x71));

    adopted(registry.triage(InboundArrival::Accepted, peer, routing(7)));
    assert_eq!(
        timeout(Duration::from_secs(3), reported.recv())
            .await
            .expect("the front was told within 3s"),
        Some(ReportedToFront::Identified(peer))
    );
    drop(handle);
}
