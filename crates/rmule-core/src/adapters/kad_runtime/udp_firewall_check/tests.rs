//! The requester's peer-TCP leg against a real listener standing in for the
//! UDP Firewall Helper: what reaches it, and how each way the link ends is
//! reported.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use rmule_net::peer::{ConnectOptions as PeerConnectOptions, PeerListener};
use rmule_peer::{ConnectionEvent, PeerEvent, PeerHandshakeContext, SideEvent, UdpPortsAdvert};
use rmule_primitives::{
    ClientId, ClientIdentity, Ed2kFileLink, Ed2kText, Ipv4Endpoint, PeerEndpoint, ServerEndpoint,
    UserHash,
};
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::{
    Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand, DownloadEvent, DownloadFailure,
    PeerTransferService, PeerWorker, PeerWorkerEvent,
};

use super::*;

fn ctx(hash: u8, nick: &str) -> PeerHandshakeContext {
    PeerHandshakeContext {
        identity: ClientIdentity::new(
            UserHash::from_bytes([hash; UserHash::BYTE_LEN]),
            Ed2kText::from_utf8(nick),
            4662,
            0x3C,
        ),
        client_id: ClientId::from_u32(0),
        ed2k_client_id: ClientId::from_u32(0),
        public_ip: None,
        connected_server: None,
    }
}

/// A helper on loopback whose hello advertises `kad_udp` (0 = no Kad). It
/// returns the first `OP_FWCHECKUDPREQ` body it receives, then hangs up — or
/// `None` if the link ends first.
async fn helper(kad_udp: u16) -> (Ipv4Endpoint, tokio::task::JoinHandle<Option<Vec<u8>>>) {
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind the helper");
    let endpoint = Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, listener.local_port());
    let task = tokio::spawn(async move {
        let options = PeerConnectOptions {
            udp_ports: Some(UdpPortsAdvert::new(0, kad_udp)),
            ..PeerConnectOptions::default()
        };
        let mut conn = listener
            .accept(ctx(0x22, "udp-helper"), options)
            .await
            .expect("the requester dials in");
        loop {
            match conn.next_event().await {
                Some(PeerEvent::Side(SideEvent::KadUdpFirewallCheckRequested { request })) => {
                    let _ = conn.shutdown().await;
                    return Some(request);
                }
                Some(PeerEvent::Connection(ConnectionEvent::Disconnected { .. })) | None => {
                    return None;
                }
                Some(_) => {}
            }
        }
    });
    (endpoint, task)
}

const REQUEST: [u8; 8] = [0x40, 0x12, 0x88, 0x13, 0x78, 0x56, 0x34, 0x12];

#[tokio::test]
async fn the_request_rides_a_completed_hello_and_a_link_that_ends_after_it_is_a_failure() {
    let (endpoint, helper) = helper(4672).await;
    let end = enact_udp_firewall_check(
        endpoint,
        REQUEST.to_vec(),
        ctx(0x11, "rmule"),
        &crate::adapters::HelloAdverts::default(),
        &crate::hello_refusals::SharedHelloRefusals::default(),
        Duration::from_secs(5),
    )
    .await;
    let received = timeout(Duration::from_secs(2), helper)
        .await
        .expect("the helper finished")
        .expect("helper task");
    assert_eq!(
        received,
        Some(REQUEST.to_vec()),
        "the node's body goes out as given"
    );
    assert_eq!(
        end,
        UdpCheckLinkEnd::Closed,
        "a link that ends after the request, with no 0x62 counted, is a failed helper"
    );
}

/// The helper dial sends the one hello every outbound connection
/// sends, so the helper learns our ports, Kad version, IPv6 and crypt support
/// as any peer would. The helper here reads the hello and hangs up, so the
/// check itself is cancelled.
#[tokio::test]
async fn the_helper_dial_s_hello_states_every_advert() {
    let helper = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind the helper");
    let endpoint = Ipv4Endpoint::new(
        Ipv4Addr::LOCALHOST,
        helper.local_addr().expect("bound").port(),
    );
    let adverts = crate::adapters::tests::hello_wire::live_adverts(
        crate::firewalled::front::BuddyView::default(),
    );
    let check = tokio::spawn(async move {
        enact_udp_firewall_check(
            endpoint,
            REQUEST.to_vec(),
            ctx(0x11, "rmule"),
            &adverts,
            &crate::hello_refusals::SharedHelloRefusals::default(),
            Duration::from_secs(5),
        )
        .await
    });
    let (mut stream, _) = timeout(Duration::from_secs(2), helper.accept())
        .await
        .expect("the dial arrives within 2s")
        .expect("accept");
    let hello = timeout(
        Duration::from_secs(2),
        crate::adapters::tests::hello_wire::read_hello_body(&mut stream),
    )
    .await
    .expect("the hello arrives within 2s");
    crate::adapters::tests::hello_wire::assert_states_live_adverts(&hello);
    drop(stream);
    assert_eq!(check.await.expect("check task"), UdpCheckLinkEnd::Cancelled);
}

#[tokio::test]
async fn a_helper_whose_hello_names_no_kad_port_is_cancelled_unasked() {
    let (endpoint, helper) = helper(0).await;
    let end = enact_udp_firewall_check(
        endpoint,
        REQUEST.to_vec(),
        ctx(0x11, "rmule"),
        &crate::adapters::HelloAdverts::default(),
        &crate::hello_refusals::SharedHelloRefusals::default(),
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(end, UdpCheckLinkEnd::Cancelled);
    assert_eq!(
        timeout(Duration::from_secs(2), helper)
            .await
            .expect("the helper finished")
            .expect("helper task"),
        None,
        "BaseClient.cpp:3972-3979: no Kad port, no request"
    );
}

/// Under our own `Required` policy the helper is still
/// dialled — plain, since its hash, the obfuscation key, is unknown — as an
/// outbound Test Connection (ADR-0046). Were it refused, the UDP check
/// would never run under `Required` and Kad UDP would never read Open. The request reaches
/// the helper as under any other policy.
#[tokio::test]
async fn a_required_policy_node_asks_its_helper_over_a_plain_test_link() {
    let (endpoint, helper) = helper(4672).await;
    let required = crate::adapters::HelloAdverts {
        obfuscation: crate::obfuscation_policy::SharedObfuscationPolicy::new(Some(
            rmule_net::peer::ObfuscationPolicy::Required,
        )),
        ..crate::adapters::HelloAdverts::default()
    };
    let end = enact_udp_firewall_check(
        endpoint,
        REQUEST.to_vec(),
        ctx(0x11, "rmule"),
        &required,
        &crate::hello_refusals::SharedHelloRefusals::default(),
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(
        timeout(Duration::from_secs(2), helper)
            .await
            .expect("the helper finished")
            .expect("helper task"),
        Some(REQUEST.to_vec()),
        "the request reaches the helper under Required"
    );
    assert_eq!(end, UdpCheckLinkEnd::Closed);
}

/// kno's `ab483654` answer over IPv6, 10 tags declared and 9 carried
/// (captured; provenance in the fixture's `meta.toml`).
const KNO_SHORT_COUNT_ANSWER: &[u8] = include_bytes!(
    "../../../../../rmule-peer/tests/fixtures/hello_refusal/captured/amule-kno-ab483654-short-count-20260924/amule_kno_op_helloanswer_short_count.bin"
);

/// A helper whose hello answer is refused (ADR-0050) is counted and raised
/// like every other refused hello, and the check is cancelled unasked: the
/// helper dial waits for the hello through the one wait every connection
/// shares.
#[tokio::test]
async fn a_helper_whose_hello_is_refused_is_reported_and_cancelled_unasked() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind the helper");
    let endpoint = Ipv4Endpoint::new(
        Ipv4Addr::LOCALHOST,
        listener.local_addr().expect("bound").port(),
    );
    let helper = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("the requester dials in");
        let mut hello = [0u8; 512];
        let _ = socket.read(&mut hello).await;
        socket
            .write_all(KNO_SHORT_COUNT_ANSWER)
            .await
            .expect("answer");
        let _ = socket.read(&mut hello).await;
    });
    let diagnostics = crate::diagnostics::DiagnosticsState::default();
    let (events_tx, mut events) = mpsc::channel(4);
    let refusals = crate::hello_refusals::SharedHelloRefusals::default();
    refusals.install(diagnostics, events_tx.downgrade());

    let end = enact_udp_firewall_check(
        endpoint,
        REQUEST.to_vec(),
        ctx(0x11, "rmule"),
        &crate::adapters::HelloAdverts::default(),
        &refusals,
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(end, UdpCheckLinkEnd::Cancelled);
    let raised = timeout(Duration::from_secs(2), events.recv())
        .await
        .expect("raised within 2s")
        .expect("an event");
    assert!(
        matches!(raised, CoreEvent::PeerHelloRefused { .. }),
        "the refusal is raised, got {raised:?}"
    );
    helper.abort();
}

#[tokio::test]
async fn a_refused_dial_is_cancelled() {
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let end = enact_udp_firewall_check(
        Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, port),
        REQUEST.to_vec(),
        ctx(0x11, "rmule"),
        &crate::adapters::HelloAdverts::default(),
        &crate::hello_refusals::SharedHelloRefusals::default(),
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(end, UdpCheckLinkEnd::Cancelled);
}

#[tokio::test]
async fn a_helper_the_peer_roster_already_knows_is_cancelled_unasked() {
    // aMule's last `QueryNextClient` gate before a dial
    // (`ClientList.cpp:1204-1211`): a helper IP the client list already
    // knows is refused before it is ever tested. The endpoint below dials
    // nothing real — a real dial would either hang or need a listener this
    // test never binds — so a prompt `Cancelled` on the pump proves the gate
    // ran instead of the dial.
    let helper_ip = Ipv4Addr::new(203, 0, 113, 50);
    let roster = SharedPeerRoster::default();
    roster.mark_known(
        crate::peer_roster::PeerRelation::Upload,
        Ipv4Endpoint::new(helper_ip, 4761),
    );

    let (tx, mut rx) = mpsc::channel(4);

    run_udp_firewall_check(
        Ipv4Endpoint::new(helper_ip, 4700),
        REQUEST.to_vec(),
        ctx(0x11, "rmule"),
        crate::adapters::HelloAdverts::default(),
        crate::hello_refusals::SharedHelloRefusals::default(),
        tx.downgrade(),
        roster,
    )
    .await;

    let command = timeout(Duration::from_millis(200), rx.recv())
        .await
        .expect("the gate reports at once, never dialing")
        .expect("a command was pushed");
    assert!(
        matches!(command, KadPumpCommand::UdpFirewallCheckCancelled(ip) if ip == helper_ip),
        "a known helper is cancelled unasked, freeing the slot for the next candidate"
    );
}

/// A `SourceLookupService` that answers every lookup with the same outcome —
/// the one High-ID source below. Not `rmule_testkit`'s own
/// `StaticSourceLookup`: that crate depends on this one, so using it from
/// this crate's own unit tests links two separate copies of `rmule_core` and
/// every `Core`-emitted type stops matching (`E0308`, "multiple different
/// versions of crate `rmule_core`").
#[derive(Clone)]
struct FixedSourceLookup {
    outcome: crate::SourceLookupOutcome,
}

impl crate::SourceLookupService for FixedSourceLookup {
    async fn lookup_sources(
        &mut self,
        _target: rmule_primitives::SourceLookupTarget,
    ) -> Result<crate::SourceLookupOutcome, DownloadFailure> {
        Ok(self.outcome.clone())
    }
}

/// A `PeerTransferService` whose worker connects, then hangs up on its own —
/// the ordinary way a peer worker ends (a hangup, an error) — the moment the
/// test signals `disconnect`, rather than on any `Shutdown` command (an
/// operator's `CancelDownload` stops the fleet loop's `select!` on its own
/// stop signal without draining the fact stream at all, so a `Disconnected`
/// sent only in reply to one would never be seen).
struct DisconnectingPeerTransfer {
    disconnect: std::sync::Arc<tokio::sync::Notify>,
}

impl PeerTransferService for DisconnectingPeerTransfer {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        let advertised = PeerWorkerEvent::every_part(file.size);
        let (command_tx, mut command_rx) = mpsc::channel(8);
        let (event_tx, event_rx) = mpsc::channel(8);
        let disconnect = self.disconnect.clone();
        tokio::spawn(async move {
            let _ = event_tx.send(PeerWorkerEvent::Connected).await;
            let _ = event_tx.send(advertised).await;
            let _ = event_tx.send(PeerWorkerEvent::SlotGranted).await;
            disconnect.notified().await;
            let _ = event_tx.send(PeerWorkerEvent::Disconnected).await;
            // Drain whatever the runner sent meanwhile (a slot ask, a part) so
            // its sender never blocks on a full channel.
            while command_rx.recv().await.is_some() {}
        });
        Ok(PeerWorker::new(peer, command_tx, event_rx))
    }
}

#[tokio::test]
async fn a_download_workers_connect_marks_the_roster_and_the_runs_end_forgets_it() {
    let out_dir = tempfile::tempdir().unwrap();
    // The download runner's fleet loop is the roster's other
    // writer. This drives a real worker session — a live `Core`, a scripted
    // `PeerTransferService` — through the fleet's own `Connected`/
    // `Disconnected` write sites, rather than hand-calling `mark_known`, then
    // proves both the requester gate above reads a download-fed mark exactly
    // like an upload-fed one, and that ending the worker forgets it.
    // The IP `ClientId::from_u32(0x0100_007F)` decodes to (a High ID *is* the
    // client's IPv4 address as a little-endian `u32`): its `to_le_bytes()`
    // are `[0x7F, 0x00, 0x00, 0x01]`, i.e. 127.0.0.1.
    let peer_ip = Ipv4Addr::new(127, 0, 0, 1);

    let store = crate::open_durable_store_in_memory().expect("in-memory store opens");
    let source = FixedSourceLookup {
        outcome: crate::SourceLookupOutcome {
            client_id: ClientId::from_u32(0x0100_007F),
            sources: vec![
                rmule_primitives::SourceSighting::plain(
                    rmule_primitives::PeerSource::new(ClientId::from_u32(42), 4662),
                    rmule_primitives::Informant::Own,
                ),
                rmule_primitives::SourceSighting::plain(
                    rmule_primitives::PeerSource::new(ClientId::from_u32(0x0100_007F), 4663),
                    rmule_primitives::Informant::Own,
                ),
            ],
        },
    };
    let disconnect = std::sync::Arc::new(tokio::sync::Notify::new());
    let builder = Core::builder(CoreConfig::default(), store)
        .settings(crate::CoreSettings {
            download_dir: Some(out_dir.path().to_path_buf()),
            ..crate::CoreSettings::default()
        })
        .source_lookup(source)
        .peer_transfer(DisconnectingPeerTransfer {
            disconnect: disconnect.clone(),
        });
    let roster = builder.shared_peer_roster();
    let mut core = builder.build();

    let file = Ed2kFileLink {
        name: Ed2kText::from_utf8("example.bin"),
        size: 11,
        file_hash: rmule_primitives::FileHash::from_bytes(
            [0xAB; rmule_primitives::FileHash::BYTE_LEN],
        ),
        part_hash_set: None,
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    };
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        name: rmule_primitives::SafeFileName::clean(
            "roster-download-leg.bin",
            &rmule_primitives::FileHash::from_bytes([0; 16]),
        ),
        if_taken: crate::NameTaken::Refuse,
        kad_aich_root: None,
    }))
    .await
    .unwrap();

    // `PeerSelected` fires at the spawn *decision*, before the dial — too
    // early to prove the mark ran. `PartAssigned` only follows
    // `DownloadState::on_worker_event(Connected)`'s own `assign` call
    // (`download/state/slots.rs`), strictly after the fleet's match on
    // `PeerWorkerEvent::Connected` in the same iteration — so seeing it here
    // proves the mark already happened.
    loop {
        match next_core_event(&mut core).await {
            CoreEvent::Download(DownloadEvent::PartAssigned { .. }) => break,
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("download failed before a part was assigned: {reason:?}")
            }
            _ => {}
        }
    }
    assert!(
        roster.knows(peer_ip),
        "the fleet marked the connected peer's IP known"
    );

    // The requester gate (ADR-0058), exercised end to end against
    // a roster the download side fed for real: a helper at this same IP is
    // cancelled unasked, exactly as an upload-known one is above.
    let (tx, mut rx) = mpsc::channel(4);
    run_udp_firewall_check(
        Ipv4Endpoint::new(peer_ip, 4700),
        REQUEST.to_vec(),
        ctx(0x11, "rmule"),
        crate::adapters::HelloAdverts::default(),
        crate::hello_refusals::SharedHelloRefusals::default(),
        tx.downgrade(),
        roster.clone(),
    )
    .await;
    let command = timeout(Duration::from_millis(200), rx.recv())
        .await
        .expect("the gate reports at once, never dialing")
        .expect("a command was pushed");
    assert!(
        matches!(command, KadPumpCommand::UdpFirewallCheckCancelled(ip) if ip == peer_ip),
        "a download-known peer is cancelled unasked too"
    );
    // The helper responder's bias (the sibling gate) reads the identical
    // `knows()` call proven above; driving its own inbound triage would need
    // a second live peer link this test does not otherwise need, and
    // `the_helper_responder_flags_a_biased_result_for_a_caller_the_peer_roster_knows`
    // (kad crate) already proves the bias itself reads it correctly.
    assert!(
        roster.knows(peer_ip),
        "the same read the helper's bias consults still finds the peer known"
    );

    // Let the worker's link fail while it transfers. `on_worker_event
    // (Disconnected)` releases its in-flight part, and its record stands
    // queued without a rank, aMule's `DS_ONQUEUE` client known after its
    // socket closed (ADR-0090): the worker's relation goes, the queued one
    // holds the IP.
    disconnect.notify_one();
    let download_id = loop {
        match next_core_event(&mut core).await {
            CoreEvent::Download(DownloadEvent::PartReleased { download_id, .. }) => {
                break download_id;
            }
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. }) => {
                panic!("the sole worker disconnected — nothing to complete")
            }
            _ => {}
        }
    };
    loop {
        if let CoreEvent::Download(DownloadEvent::SourceRemoteQueued { .. }) =
            next_core_event(&mut core).await
        {
            break;
        }
    }
    assert!(
        roster.knows(peer_ip),
        "the source standing queued is still known"
    );

    // The run's end forgets every relation it held.
    core.send(CoreCommand::Download(DownloadCommand::CancelDownload {
        download_id,
    }))
    .await
    .unwrap();
    loop {
        if let CoreEvent::Download(DownloadEvent::DownloadCancelled { .. }) =
            next_core_event(&mut core).await
        {
            break;
        }
    }
    assert!(!roster.knows(peer_ip), "the run's end forgot the IP");
}

/// Await the next fact from `core`, same as `Core::next_event` but with a
/// bounded wait, so a stalled fixture times out instead of hanging the suite.
async fn next_core_event(core: &mut Core) -> CoreEvent {
    timeout(Duration::from_secs(2), core.next_event())
        .await
        .expect("core emitted next event within 2s")
        .expect("core event stream stayed open")
}

/// The check outlives a Kad restart (it holds its link up to 40 s): its end
/// belongs to the node that asked. The shared pump cell now holds the
/// successor's inbox, and a result that reached it would be counted against
/// whatever helper the successor engaged.
#[tokio::test]
async fn a_check_that_outlives_its_node_does_not_report_to_the_successor() {
    let helper_ip = Ipv4Addr::new(203, 0, 113, 51);
    let roster = SharedPeerRoster::default();
    roster.mark_known(
        crate::peer_roster::PeerRelation::Upload,
        Ipv4Endpoint::new(helper_ip, 4761),
    );
    let (predecessor_tx, predecessor_rx) = mpsc::channel(4);
    let asker = predecessor_tx.downgrade();
    drop((predecessor_tx, predecessor_rx));
    let successor = crate::adapters::kad_runtime::SharedKadPump::default();
    let (successor_tx, mut successor_rx) = mpsc::channel(4);
    successor.install_for_good(successor_tx);

    run_udp_firewall_check(
        Ipv4Endpoint::new(helper_ip, 4700),
        REQUEST.to_vec(),
        ctx(0x11, "rmule"),
        crate::adapters::HelloAdverts::default(),
        crate::hello_refusals::SharedHelloRefusals::default(),
        asker,
        roster,
    )
    .await;

    assert!(
        successor_rx.try_recv().is_err(),
        "the old node's result is dropped, not delivered to the node now running"
    );
}
