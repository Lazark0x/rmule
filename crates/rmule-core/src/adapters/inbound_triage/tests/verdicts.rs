//! Each **Awaited Inbound** verdict carried out on a real connection, through
//! the *production* serve adapter: a stream rmule raised toward a named
//! target enters at
//! [`SharedTunnelAdmit::admit_dialed_toward`](crate::adapters::SharedTunnelAdmit),
//! meets the IP filter and the ban gate there, and reaches the real
//! `triage_inbound_connection`, which asks the registry on the hello.
//!
//! The stream is an ordinary loopback `TcpStream` rather than a punched uTP
//! Tunnel: the target travels with the stream, so what the triage does with
//! it cannot depend on the transport underneath. The Tunnel itself is proven
//! in `crate::natt::front::adoption`; which registration a verdict picks is
//! the registry's own tests'.

use std::net::{IpAddr, SocketAddr};

use rmule_net::peer::PeerStreamRole;
use rmule_primitives::PeerEndpoint;
use rmule_testkit::{FakePeer, PeerScript};
use tokio::net::TcpStream;

use crate::adapters::serve_runtime::{RuntimeServeRuntimeService, ServeRuntimeService};
use crate::adapters::tests::{dialed_serve_ctx, loopback_blocking_ip_filter};
use crate::adapters::{AdoptionBrief, AwaitedInboundHandle, SharedTunnelAdmit};
use crate::ban_store::SharedBanStore;
use crate::ip_filter::SharedIpFilter;

use super::*;

fn hash(byte: u8) -> UserHash {
    UserHash::from_bytes([byte; UserHash::BYTE_LEN])
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
/// back under.
fn callback_key() -> CallbackKey {
    CallbackKey {
        server: None,
        low_id: ClientId::from_u32(7),
        kad_port: None,
    }
}

/// Claim `target` the way the runner's fallback arm does; the receiver is
/// where an adoption arrives.
fn claim(
    awaited: &AwaitedInbound,
    target: UserHash,
) -> (
    AwaitedInboundHandle,
    mpsc::Receiver<(CallbackKey, crate::adapters::PeerWorker)>,
) {
    let (adopt_tx, adopt_rx) = mpsc::channel(4);
    let registration = awaited.register(callback_key(), adopt_tx, mpsc::channel(4).0);
    registration.claim_tunnel(
        target,
        AdoptionBrief {
            own_status: rmule_peer::PartBitmap::downloader_empty(0),
            want_sources: true,
            file: file(),
        },
        false,
    );
    (registration, adopt_rx)
}

/// A serve adapter started the production way — listener bound, login to a
/// dead port failing harmlessly — with the two gates and the registry wired
/// in.
async fn serving_node(
    awaited: &AwaitedInbound,
    ban_store: SharedBanStore,
    ip_filter: SharedIpFilter,
) -> (RuntimeServeRuntimeService, SharedTunnelAdmit) {
    let admit = SharedTunnelAdmit::default();
    let mut serve = RuntimeServeRuntimeService::new()
        .with_tunnel_admit(admit.clone())
        .with_awaited_inbound(awaited.clone())
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

/// Dial a `FakePeer` that answers our hello as `hello_hash`, and hand the
/// open stream to the admit seam as a path raised toward `target`.
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

/// The first event on the admitted connection, which is the verdict as the
/// serve pipeline sees it: `Readopted` for an adoption, `Identified` for the
/// serve road, `Disconnected` for a refusal.
async fn first_serve_event(serve: &mut RuntimeServeRuntimeService) -> Option<ServeInput> {
    let budget = Duration::from_secs(5);
    let mut conn = timeout(budget, serve.accept())
        .await
        .ok()
        .flatten()
        .expect("a path that clears the gates is surfaced");
    timeout(budget, conn.next_event()).await.ok().flatten()
}

/// `Adopt`: the claimed path's peer says it is the target, so the connection
/// becomes that download's worker, handed over under the callback's key,
/// and never reaches the serve pipeline.
#[tokio::test]
async fn an_adoption_hands_the_connection_to_the_download() {
    let target = hash(0xAB);
    let awaited = AwaitedInbound::default();
    let (_registration, mut adopt_rx) = claim(&awaited, target);
    let (mut serve, admit) = serving_node(
        &awaited,
        SharedBanStore::default(),
        SharedIpFilter::default(),
    )
    .await;

    let _serving = punched_path_toward(&admit, target, target).await;
    assert!(
        matches!(
            first_serve_event(&mut serve).await,
            Some(ServeInput::Readopted)
        ),
        "the serve registration is retracted, not identified: this path was claimed"
    );
    let (key, _worker) = timeout(Duration::from_secs(3), adopt_rx.recv())
        .await
        .expect("the adoption reached the claiming download within 3s")
        .expect("the adopt channel stayed open");
    assert_eq!(key, callback_key());
}

/// A revision the session reads between the hello and the hand-over reaches
/// the download: the worker's identity stream ends on the revised identity,
/// not the one the accept took.
#[tokio::test]
async fn an_adopted_worker_ends_on_the_identity_the_session_holds() {
    use crate::adapters::PeerWorkerEvent;

    let target = hash(0xAB);
    let awaited = AwaitedInbound::default();
    let (_registration, mut adopt_rx) = claim(&awaited, target);
    let (mut serve, admit) = serving_node(
        &awaited,
        SharedBanStore::default(),
        SharedIpFilter::default(),
    )
    .await;

    // A pre-0.42 mule: its hello names no source exchange, and the
    // `OP_EMULEINFO` straight after it states version 2.
    let peer = FakePeer::bind().await;
    let addr = peer.addr();
    let _serving = peer.spawn(PeerScript {
        hello_user_hash: target,
        legacy_mule_info: Some(2),
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

    assert!(matches!(
        first_serve_event(&mut serve).await,
        Some(ServeInput::Readopted)
    ));
    let (_, mut worker) = timeout(Duration::from_secs(3), adopt_rx.recv())
        .await
        .expect("the adoption reached the claiming download within 3s")
        .expect("the adopt channel stayed open");
    let mut askable = Vec::new();
    timeout(Duration::from_secs(3), async {
        while let Some(event) = worker.next_event().await {
            if let PeerWorkerEvent::Identity(identity) = event {
                askable.push(identity.source_exchange().askable());
                if askable.last() == Some(&true) {
                    break;
                }
            }
        }
    })
    .await
    .expect("the revised identity reached the download within 3s");
    assert_eq!(
        (askable.first(), askable.last()),
        (Some(&false), Some(&true)),
        "the accept's identity first, then the revisions the session read after it"
    );
}

/// `Adopt`, for a download that ended between the verdict and the hand-over:
/// no worker is built for nobody, and the connection takes the serve road.
#[tokio::test]
async fn an_adoption_for_a_download_that_ended_takes_the_serve_road() {
    let target = hash(0xAB);
    let awaited = AwaitedInbound::default();
    let (_registration, adopt_rx) = claim(&awaited, target);
    drop(adopt_rx);
    let (mut serve, admit) = serving_node(
        &awaited,
        SharedBanStore::default(),
        SharedIpFilter::default(),
    )
    .await;

    let _serving = punched_path_toward(&admit, target, target).await;
    assert!(
        matches!(
            first_serve_event(&mut serve).await,
            Some(ServeInput::Connection(ConnectionEvent::Identified { identity }))
                if identity.user_hash() == target
        ),
        "the connection is served as an ordinary inbound peer"
    );
}

/// `Mismatch`: a peer that answers on the punched path but identifies as
/// somebody else is refused and its connection closed, never served.
#[tokio::test]
async fn a_mismatch_closes_the_connection() {
    let target = hash(0xAB);
    let awaited = AwaitedInbound::default();
    let (_registration, mut adopt_rx) = claim(&awaited, target);
    let (mut serve, admit) = serving_node(
        &awaited,
        SharedBanStore::default(),
        SharedIpFilter::default(),
    )
    .await;

    let stranger = punched_path_toward(&admit, target, hash(0x11)).await;
    assert!(
        matches!(
            first_serve_event(&mut serve).await,
            Some(ServeInput::Connection(ConnectionEvent::Disconnected { .. }))
        ),
        "a refused adoption is not served either — nothing asked for this path"
    );
    assert!(adopt_rx.try_recv().is_err());
    // The script task ends at EOF, so its return is the proof the connection
    // was closed rather than merely ignored.
    timeout(Duration::from_secs(3), stranger)
        .await
        .expect("the refused connection is closed within 3s")
        .expect("the counterparty script ran");
}

/// `Unclaimed`: nobody waits for this peer, so the path is an ordinary
/// inbound peer on the serve road (ADR-0091).
#[tokio::test]
async fn an_unclaimed_connection_takes_the_serve_road() {
    let awaited = AwaitedInbound::default();
    let (mut serve, admit) = serving_node(
        &awaited,
        SharedBanStore::default(),
        SharedIpFilter::default(),
    )
    .await;

    let _serving = punched_path_toward(&admit, hash(0xAB), hash(0xAB)).await;
    assert!(
        matches!(
            first_serve_event(&mut serve).await,
            Some(ServeInput::Connection(ConnectionEvent::Identified { identity }))
                if identity.user_hash() == hash(0xAB)
        ),
        "an unclaimed path is an ordinary inbound peer"
    );
}

/// The gates come before the question: a banned or IP-filtered peer is
/// refused before the registry is asked, so a punched path can never be the
/// way back in for an address this node has shut out.
#[tokio::test]
async fn a_banned_or_filtered_peers_path_is_refused_before_the_registry_is_asked() {
    for (ban_store, ip_filter) in [
        (banned_loopback().await, SharedIpFilter::default()),
        (
            SharedBanStore::default(),
            Arc::new(std::sync::RwLock::new(loopback_blocking_ip_filter())),
        ),
    ] {
        let target = hash(0xAB);
        let awaited = AwaitedInbound::default();
        let (_registration, mut adopt_rx) = claim(&awaited, target);
        let (mut serve, admit) = serving_node(&awaited, ban_store, ip_filter).await;

        let _serving = punched_path_toward(&admit, target, target).await;
        assert!(
            timeout(Duration::from_millis(500), serve.accept())
                .await
                .ok()
                .flatten()
                .is_none(),
            "a gated path never becomes a serve connection"
        );
        assert!(adopt_rx.try_recv().is_err(), "nor is it adopted");
        assert!(
            matches!(
                awaited.triage(InboundArrival::DialedToward(target), target, callback_key()),
                InboundVerdict::Adopt(_)
            ),
            "and the registry was never asked, so the claim still stands"
        );
    }
}

/// A ban store holding the only address a loopback test can dial from.
async fn banned_loopback() -> SharedBanStore {
    let store = SharedBanStore::default();
    store
        .lock()
        .await
        .ban(IpAddr::V4(Ipv4Addr::LOCALHOST), Instant::now());
    store
}
