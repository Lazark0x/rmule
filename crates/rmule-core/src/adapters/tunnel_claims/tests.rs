//! The adoption road, driven through the *production* serve adapter: a stream
//! rmule raised toward a named target enters at
//! [`SharedTunnelAdmit::admit_dialed_toward`](crate::adapters::SharedTunnelAdmit),
//! meets the IP filter and the ban gate in `accept()`, and reaches the real
//! `triage_inbound_connection`, which decides on the hello.
//!
//! The stream here is an ordinary loopback `TcpStream` rather than a punched
//! uTP Tunnel, and that is exactly the point being made: the claim travels
//! with the stream, so what the adoption road does with it cannot depend on
//! which transport is underneath. The Tunnel itself — raised by two real NAT-T
//! fronts over real UDP, with a download taking a part over it — is proven in
//! `crate::natt::front::adoption`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use rmule_net::peer::PeerStreamRole;
use rmule_primitives::{ClientId, Ed2kFileLink, Ed2kText, FileHash, Ipv4Endpoint, PeerEndpoint};
use rmule_testkit::{FakePeer, PeerScript};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::adapters::serve_runtime::{
    RuntimeServeRuntimeService, ServeConnEvent, ServeRuntimeService,
};
use crate::adapters::tests::{dialed_serve_ctx, loopback_blocking_ip_filter};
use crate::ban_store::SharedBanStore;
use crate::ip_filter::SharedIpFilter;

use super::*;

fn hash(byte: u8) -> UserHash {
    UserHash::from_bytes([byte; UserHash::BYTE_LEN])
}

/// A User Hash whose four 4-byte words all differ.
fn uneven_hash(seed: u8) -> UserHash {
    let mut bytes = [0u8; UserHash::BYTE_LEN];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = seed.wrapping_add(u8::try_from(index).expect("16 bytes").wrapping_mul(0x2B));
    }
    UserHash::from_bytes(bytes)
}

fn file() -> Ed2kFileLink {
    Ed2kFileLink {
        name: Ed2kText::from_utf8("claimed"),
        size: 4096,
        file_hash: FileHash::from_bytes([0xCD; FileHash::BYTE_LEN]),
        part_hash_set: None,
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    }
}

/// The callback a claim runs beside — what the adopted worker is reported
/// back under, so the brain ends one pending callback either way.
fn callback_key() -> CallbackKey {
    CallbackKey {
        server: None,
        low_id: ClientId::from_u32(7),
    }
}

/// A serve adapter started the production way — listener bound, login to a
/// dead port failing harmlessly — with the two gates and the claim table
/// wired in. A serving node is what a punched path needs on this side:
/// without one there is no handshake context to answer a hello with.
async fn serving_node(
    claims: &SharedTunnelClaims,
    ban_store: SharedBanStore,
    ip_filter: SharedIpFilter,
) -> (RuntimeServeRuntimeService, SharedTunnelAdmit) {
    // Bind then drop for a port whose connect fails fast: a failed login never
    // fails the serve activity — only binding the listener does.

    let admit = SharedTunnelAdmit::default();
    let mut serve = RuntimeServeRuntimeService::new()
        .with_tunnel_admit(admit.clone())
        .with_tunnel_claims(claims.clone())
        .with_ban_store(ban_store)
        .with_ip_filter(ip_filter);
    serve
        .start(
            dialed_serve_ctx().identity,
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        )
        .await
        .expect("the listener binds");
    (serve, admit)
}

/// Dial a `FakePeer` that will answer our hello as `hello_hash`, and hand the
/// open stream to the admit seam as a path raised toward `target` — the shape
/// `natt::front::tunnels::adopt` hands a dialed Tunnel over in.
async fn punched_path_toward(
    admit: &SharedTunnelAdmit,
    target: UserHash,
    hello_hash: UserHash,
) -> tokio::task::JoinHandle<rmule_testkit::PeerStats> {
    let peer = FakePeer::bind().await;
    let addr = peer.addr();
    let serving = peer.spawn(PeerScript {
        hello_user_hash: hello_hash,
        ..PeerScript::serving(file().file_hash, vec![0u8; 4096])
    });
    let stream = TcpStream::connect(SocketAddr::V4(addr))
        .await
        .expect("the counterparty is listening");
    let endpoint = PeerEndpoint::V4(Ipv4Endpoint::new(*addr.ip(), addr.port()));
    admit
        .admit_dialed_toward(stream, endpoint, PeerStreamRole::Dialer, target)
        .await
        .expect("a serving node admits the path");
    serving
}

/// Register a claim the way the runner's fallback arm does.
async fn claim(
    claims: &SharedTunnelClaims,
    target: UserHash,
) -> (
    mpsc::Receiver<(CallbackKey, PeerWorker)>,
    mpsc::Receiver<(CallbackKey, crate::diagnostics::NattRetirement)>,
) {
    let (adopt_tx, adopt_rx) = mpsc::channel(4);
    let (retire_tx, retire_rx) = mpsc::channel(4);
    claims
        .register(
            target,
            PendingTunnelEntry {
                own_status: rmule_peer::PartBitmap::downloader_empty(0),
                want_sources: true,
                file: file(),
                callback: callback_key(),
                adopt_tx,
                retire_tx,
                dial_back: false,
            },
        )
        .await;
    (adopt_rx, retire_rx)
}

/// What the serve pipeline made of an admitted path: its first event.
///
/// `accept()` surfaces every path that clears the gates — the adopt/serve
/// split happens *after*, in the per-connection triage, once the hello is in.
/// So the first event on the connection is the verdict: `Readopted` retracts
/// the serve registration for a download that claimed it, `Identified` is the
/// serve road proceeding, and `Disconnected` is a refusal.
async fn first_serve_event(
    serve: &mut RuntimeServeRuntimeService,
    budget: Duration,
) -> Option<ServeConnEvent> {
    let mut conn = timeout(budget, serve.accept())
        .await
        .ok()
        .flatten()
        .expect("a path that clears the gates is surfaced");
    timeout(budget, conn.next_event()).await.ok().flatten()
}

/// Whether the serve pipeline ever surfaced a path at all — what a gate
/// refusal looks like from here.
async fn surfaced_within(serve: &mut RuntimeServeRuntimeService, budget: Duration) -> bool {
    timeout(budget, serve.accept())
        .await
        .ok()
        .flatten()
        .is_some()
}

/// An adoption this table grants reports the peer its own hello
/// confirmed back to the front, through the exact sender a front installs at
/// `SharedTunnelClaims::install_risen` — the same seam
/// `PunchedPathGuard::drop` reports a closed path through. Nothing else here
/// can make that report: `rule` only spends the claim, and has no way back to
/// the front that owns the ledgers a confirmed peer's attempt and hold live
/// on.
#[tokio::test]
async fn an_adoption_reports_the_confirmed_peer_back_to_the_front() {
    let target = hash(0xAB);
    let claims = SharedTunnelClaims::default();
    let (risen, mut identified_rx) = crate::natt::front::NattRisenSender::test_pair();
    claims.install_risen(risen);
    let (mut adopt_rx, _retire_rx) = claim(&claims, target).await;
    let (mut serve, admit) = serving_node(
        &claims,
        SharedBanStore::default(),
        SharedIpFilter::default(),
    )
    .await;

    let _serving = punched_path_toward(&admit, target, target).await;
    first_serve_event(&mut serve, Duration::from_secs(5)).await;
    let (_key, worker) = timeout(Duration::from_secs(3), adopt_rx.recv())
        .await
        .expect("the adoption reached the claiming download within 3s")
        .expect("the adopt channel stayed open");
    drop(worker);

    let reported = timeout(Duration::from_secs(3), identified_rx.recv())
        .await
        .expect("the adoption reported the confirmed peer within 3s")
        .expect("the front's risen sender stayed open");
    assert_eq!(
        reported,
        crate::natt::front::ReportedToFront::Identified(target),
        "the adoption reports the peer its own hello confirmed"
    );
}

/// The claimed path's peer says it is the target: the connection becomes that
/// download's worker, reported under the *callback's* key, and never reaches
/// the serve pipeline.
#[tokio::test]
async fn a_claimed_paths_peer_that_is_the_target_becomes_the_downloads_worker() {
    let target = hash(0xAB);
    let claims = SharedTunnelClaims::default();
    let (mut adopt_rx, _retire_rx) = claim(&claims, target).await;
    let (mut serve, admit) = serving_node(
        &claims,
        SharedBanStore::default(),
        SharedIpFilter::default(),
    )
    .await;

    let _serving = punched_path_toward(&admit, target, target).await;
    assert!(
        matches!(
            first_serve_event(&mut serve, Duration::from_secs(5)).await,
            Some(ServeConnEvent::Readopted)
        ),
        "the serve registration is retracted, not identified: this path was claimed"
    );

    let (key, worker) = timeout(Duration::from_secs(3), adopt_rx.recv())
        .await
        .expect("the adoption reached the claiming download within 3s")
        .expect("the adopt channel stayed open");
    assert_eq!(
        key,
        callback_key(),
        "the worker is reported under the callback the punch ran beside"
    );
    drop(worker);
    assert!(
        matches!(
            claims.rule(target, target).await,
            TunnelClaimVerdict::Unclaimed
        ),
        "the claim is spent by the adoption it granted"
    );
}

/// The endpoint proves nothing behind a NAT: a peer that answers on the
/// punched path but identifies as somebody else is refused, its connection
/// closed, and the claim left standing for the target that may still come.
#[tokio::test]
async fn a_stranger_on_the_punched_path_is_refused_and_the_claim_stays_pending() {
    let target = hash(0xAB);
    let claims = SharedTunnelClaims::default();
    let (mut adopt_rx, _retire_rx) = claim(&claims, target).await;
    let (mut serve, admit) = serving_node(
        &claims,
        SharedBanStore::default(),
        SharedIpFilter::default(),
    )
    .await;

    let stranger = punched_path_toward(&admit, target, hash(0x11)).await;
    assert!(
        matches!(
            first_serve_event(&mut serve, Duration::from_secs(5)).await,
            Some(ServeConnEvent::Disconnected)
        ),
        "a refused adoption is not served either — nothing asked for this path"
    );
    assert!(
        adopt_rx.try_recv().is_err(),
        "no worker reaches the download that asked for another peer"
    );
    // The script task ends at EOF, so its return is the proof the connection
    // was closed rather than merely ignored.
    timeout(Duration::from_secs(3), stranger)
        .await
        .expect("the refused connection is closed within 3s")
        .expect("the counterparty script ran");
    assert!(
        matches!(
            claims.rule(target, target).await,
            TunnelClaimVerdict::Adopted(_)
        ),
        "the claim survives a stranger, because the real target may still arrive"
    );
}

/// Open a path nothing in this node aimed — the shape a target dialing us back
/// arrives in — to a `FakePeer` answering our hello as `hello_hash`.
async fn undirected_path(
    admit: &SharedTunnelAdmit,
    hello_hash: UserHash,
) -> tokio::task::JoinHandle<rmule_testkit::PeerStats> {
    let peer = FakePeer::bind().await;
    let addr = peer.addr();
    let serving = peer.spawn(PeerScript {
        hello_user_hash: hello_hash,
        ..PeerScript::serving(file().file_hash, vec![0u8; 4096])
    });
    let stream = TcpStream::connect(SocketAddr::V4(addr))
        .await
        .expect("the counterparty is listening");
    let endpoint = PeerEndpoint::V4(Ipv4Endpoint::new(*addr.ip(), addr.port()));
    admit
        .admit(stream, endpoint, PeerStreamRole::Dialer)
        .await
        .expect("a serving node admits the path");
    serving
}

/// ADR-0061 route 4's dial-back: the buddy relayed our `0x52`,
/// and the target dials us on a path nothing here aimed. A Kad candidate's
/// callback key is not an id any hello reports, so the claim is found by the
/// User Hash the hello names — and a punch claimed later for the same callback
/// does not take the dial-back's standing away.
#[tokio::test]
async fn a_buddy_callbacks_dial_back_is_adopted_by_the_hash_its_hello_names() {
    let target = hash(0xAB);
    let claims = SharedTunnelClaims::default();
    // One runner, so one pair of channels behind both registrations.
    let (adopt_tx, mut adopt_rx) = mpsc::channel(4);
    let (retire_tx, _retire_rx) = mpsc::channel(4);
    for dial_back in [true, false] {
        // The buddy callback's claim, then the twelve-second punch beside it
        // claiming the same target for the same callback.
        claims
            .register(
                target,
                PendingTunnelEntry {
                    own_status: rmule_peer::PartBitmap::downloader_empty(0),
                    want_sources: true,
                    file: file(),
                    callback: callback_key(),
                    adopt_tx: adopt_tx.clone(),
                    retire_tx: retire_tx.clone(),
                    dial_back,
                },
            )
            .await;
    }
    let (mut serve, admit) = serving_node(
        &claims,
        SharedBanStore::default(),
        SharedIpFilter::default(),
    )
    .await;

    let _serving = undirected_path(&admit, target).await;
    assert!(
        matches!(
            first_serve_event(&mut serve, Duration::from_secs(5)).await,
            Some(ServeConnEvent::Readopted)
        ),
        "the dial-back is the download's, not an ordinary inbound peer"
    );
    let (key, worker) = timeout(Duration::from_secs(3), adopt_rx.recv())
        .await
        .expect("the adoption reached the claiming download within 3s")
        .expect("the adopt channel stayed open");
    assert_eq!(
        key,
        callback_key(),
        "reported under the one pending callback"
    );
    drop(worker);
}

/// ADR-0091's rule stands for a punch's claim: a path nothing here aimed is not
/// adopted by one, even when its hello names the claimed hash — only a road
/// that asked the target to dial us may take what arrives undirected.
#[tokio::test]
async fn an_undirected_path_is_served_however_a_punch_claim_names_its_peer() {
    let target = hash(0xAB);
    let claims = SharedTunnelClaims::default();
    let (mut adopt_rx, _retire_rx) = claim(&claims, target).await;
    let (mut serve, admit) = serving_node(
        &claims,
        SharedBanStore::default(),
        SharedIpFilter::default(),
    )
    .await;

    let _serving = undirected_path(&admit, target).await;
    assert!(
        matches!(
            first_serve_event(&mut serve, Duration::from_secs(5)).await,
            Some(ServeConnEvent::Identified { user_hash, .. }) if user_hash == target
        ),
        "an accepted path takes the serve road"
    );
    assert!(adopt_rx.try_recv().is_err());
}

/// Nobody claimed this target: the path takes the serve road exactly as it did
/// before the claim table existed (ADR-0091).
#[tokio::test]
async fn an_unclaimed_path_takes_the_serve_road() {
    let claims = SharedTunnelClaims::default();
    let (mut serve, admit) = serving_node(
        &claims,
        SharedBanStore::default(),
        SharedIpFilter::default(),
    )
    .await;

    let _serving = punched_path_toward(&admit, hash(0xAB), hash(0xAB)).await;
    assert!(
        matches!(
            first_serve_event(&mut serve, Duration::from_secs(5)).await,
            Some(ServeConnEvent::Identified { user_hash, .. }) if user_hash == hash(0xAB)
        ),
        "an unclaimed path is an ordinary inbound peer"
    );
}

/// The gates are not the serve road's private property: a banned or
/// IP-filtered peer is refused before any claim is consulted, so a punched
/// path can never be the way back in for an address this node has shut out.
#[tokio::test]
async fn a_banned_or_filtered_peers_path_is_refused_before_the_claim() {
    for (ban_store, ip_filter) in [
        (banned_loopback().await, SharedIpFilter::default()),
        (
            SharedBanStore::default(),
            Arc::new(std::sync::RwLock::new(loopback_blocking_ip_filter())),
        ),
    ] {
        let target = hash(0xAB);
        let claims = SharedTunnelClaims::default();
        let (mut adopt_rx, _retire_rx) = claim(&claims, target).await;
        let (mut serve, admit) = serving_node(&claims, ban_store, ip_filter).await;

        let _serving = punched_path_toward(&admit, target, target).await;
        assert!(
            !surfaced_within(&mut serve, Duration::from_millis(500)).await,
            "a gated path never becomes a serve connection"
        );
        assert!(
            adopt_rx.try_recv().is_err(),
            "a gated path is not adopted either"
        );
        assert!(
            matches!(
                claims.rule(target, target).await,
                TunnelClaimVerdict::Adopted(_)
            ),
            "and the claim was never consulted, so it still stands"
        );
    }
}

/// A ban store holding the only address a loopback test can dial from.
async fn banned_loopback() -> SharedBanStore {
    let store = SharedBanStore::default();
    store
        .lock()
        .await
        .ban(IpAddr::V4(Ipv4Addr::LOCALHOST), std::time::Instant::now());
    store
}

/// Two downloads claim one target (ADR-0107): each retracts only its own
/// claim, and the attempt is abandoned only when the last claimant lets go —
/// a download's end never strands the other.
#[tokio::test]
async fn each_download_retracts_only_its_own_claim_and_the_last_abandons_the_attempt() {
    let target = uneven_hash(0xAB);
    let claims = SharedTunnelClaims::default();
    let (risen, mut reported_rx) = crate::natt::front::NattRisenSender::test_pair();
    claims.install_risen(risen);
    let (first, _first_rx) = mpsc::channel(4);
    let (second, _second_rx) = mpsc::channel(4);
    for adopt_tx in [first.clone(), second.clone()] {
        claims
            .register(
                target,
                PendingTunnelEntry {
                    own_status: rmule_peer::PartBitmap::downloader_empty(0),
                    want_sources: true,
                    file: file(),
                    callback: callback_key(),
                    adopt_tx,
                    retire_tx: mpsc::channel(1).0,
                    dial_back: false,
                },
            )
            .await;
    }

    assert!(claims.retract(target, &first).await);
    assert!(!claims.retract(target, &first).await, "already gone");
    assert!(
        timeout(Duration::from_millis(200), reported_rx.recv())
            .await
            .is_err(),
        "the second download still claims the target"
    );
    assert!(claims.retract(target, &second).await);
    assert_eq!(
        timeout(Duration::from_secs(3), reported_rx.recv())
            .await
            .expect("the front was told within 3s"),
        Some(crate::natt::front::ReportedToFront::Abandoned(target))
    );
}

/// Two downloads claim one target: the oldest takes the Tunnel, the younger
/// keeps its claim for the next one, and a retirement reaches both.
#[tokio::test]
async fn the_oldest_claim_takes_the_tunnel_and_a_retirement_reaches_every_claimant() {
    let target = uneven_hash(0x5C);
    let claims = SharedTunnelClaims::default();
    let (first, _first_rx) = mpsc::channel(4);
    let (second, _second_rx) = mpsc::channel(4);
    let (first_retire, mut first_retired) = mpsc::channel(1);
    let (second_retire, mut second_retired) = mpsc::channel(1);
    for (adopt_tx, retire_tx) in [
        (first.clone(), first_retire),
        (second.clone(), second_retire),
    ] {
        claims
            .register(
                target,
                PendingTunnelEntry {
                    own_status: rmule_peer::PartBitmap::downloader_empty(0),
                    want_sources: true,
                    file: file(),
                    callback: callback_key(),
                    adopt_tx,
                    retire_tx,
                    dial_back: false,
                },
            )
            .await;
    }

    assert!(claims.retire(target, AttemptRetirement::ServerSilent).await);
    assert!(first_retired.try_recv().is_ok());
    assert!(second_retired.try_recv().is_ok());

    match claims.rule(target, target).await {
        TunnelClaimVerdict::Adopted(entry) => assert!(entry.adopt_tx.same_channel(&first)),
        _ => panic!("the oldest claim takes the Tunnel"),
    }
    match claims.rule(target, target).await {
        TunnelClaimVerdict::Adopted(entry) => assert!(entry.adopt_tx.same_channel(&second)),
        _ => panic!("the younger claim waited for the next Tunnel"),
    }
}
