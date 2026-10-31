//! A serve activity started before the Registry Check's first look ended
//! knows no share set yet (ADR-0031): what a peer says waits for the first
//! read, because an answer from a set nobody read calls a shared file unknown.

use super::super::read_share_set;
use super::*;
use crate::registry_check::WithheldRows;
use rmule_peer::{PartBitmap, PartStatusTail};

const FILE: FileHash = FileHash::from_bytes([0x33; FileHash::BYTE_LEN]);
const SIZE: u64 = 4096;

/// The row of `FILE`, in a registry no look has ruled on.
fn share_file(registry: &DurableSharedFileRegistry) {
    registry
        .share(SharedFileEntry {
            file_hash: FILE,
            file_size: SIZE,
            path: "/shared/early.bin".into(),
            name: "early.bin".into(),
            source: ShareSource::Explicit,
            modified: None,
            part_hashes: Vec::new(),
        })
        .unwrap();
}

/// A serve task started before the look, and the ends a test drives it by.
struct Early {
    accept_tx: mpsc::Sender<ServeConnection>,
    share_changed_tx: mpsc::Sender<()>,
    reask_tx: mpsc::Sender<ClientUdpDatagram>,
    client_udp_rx: mpsc::Receiver<ClientUdpSend>,
    evt_rx: crate::service::EventStream,
    withheld: WithheldRows,
    stop_tx: watch::Sender<bool>,
    serve: tokio::task::JoinHandle<super::super::ServeOutcome<FakeServeRuntime>>,
}

fn serving_before_the_look() -> Early {
    let store = rmule_testkit::memory_store();
    let registry = DurableSharedFileRegistry::new(store.clone());
    share_file(&registry);
    let withheld = WithheldRows::before_start_look();
    let (accept_tx, accept_rx) = mpsc::channel(4);
    let (evt_tx, evt_rx) = crate::service::outbox(Default::default());
    let (stop_tx, stop_rx) = watch::channel(false);
    let (share_changed_tx, share_changed_rx) = mpsc::channel(8);
    let (reask_tx, reask_rx) = mpsc::channel(4);
    let (client_udp_tx, client_udp_rx) = mpsc::channel(4);
    let serve = tokio::spawn(
        ServeTask {
            bans: Default::default(),
            registry: Arc::new(registry),
            serve_runtime: FakeServeRuntime {
                bound: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4662),
                accepts: accept_rx,
            },
            queue: UploadSlotQueue::new(1, 200),
            own_identity: None,
            evt_tx,
            stop_rx,
            share_changed_rx,
            dialed_serve_rx: None,
            credit: Arc::new(DurableCreditStore::new(store)),
            held_places: crate::held_places::SharedHeldPlaces::default(),
            rerank_interval: Duration::from_secs(3600),
            reask_rx: Some(reask_rx),
            client_udp_tx: Some(client_udp_tx),
            purge_interval: Duration::from_secs(3600),
            purge_after: Duration::from_secs(3600),
            diagnostics: crate::diagnostics::DiagnosticsState::new(),
            peer_roster: crate::peer_roster::SharedPeerRoster::default(),
            withheld: withheld.clone(),
            read_failed_tx: None,
            served: Default::default(),
        }
        .run(),
    );
    Early {
        accept_tx,
        share_changed_tx,
        reask_tx,
        client_udp_rx,
        evt_rx,
        withheld,
        stop_tx,
        serve,
    }
}

/// Every task has run until it has nothing left to do: the paused clock moves
/// only once the runtime is idle.
async fn all_have_had_their_turn() {
    tokio::time::sleep(Duration::from_secs(1)).await;
}

impl Early {
    /// The look's end as the actor enacts it: the cell, then the trigger.
    async fn look_ends(&mut self) {
        self.withheld.looked();
        self.share_changed_tx.send(()).await.unwrap();
        next_serve_event(&mut self.evt_rx, |e| {
            matches!(e, ServeEvent::FilesAnnounced { .. })
        })
        .await;
    }

    async fn stop(self) {
        let _ = self.stop_tx.send(true);
        let _ = self.serve.await;
    }
}

/// The dial-back's order on a slow start: the link is up and the requester's
/// name ask is in while the look runs. `ClientTCPSocket.cpp:442-447` leaves a
/// file it does not share unanswered, so an ask folded against no set meets
/// silence for good, and the status ask behind it is told no such file
/// (`:503-533`). Stock asks in this order too; it is a link's first words.
#[tokio::test(start_paused = true)]
async fn a_links_first_asks_wait_for_the_look_and_are_answered_from_the_set() {
    let mut early = serving_before_the_look();
    let peer = peer_at([203, 0, 113, 9], 4000);
    let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
    let (conn_tx, conn_rx) = mpsc::channel(16);
    early
        .accept_tx
        .send(ServeConnection::new(peer, cmd_tx, conn_rx))
        .await
        .unwrap();
    let hello = HelloFacts::of(UserHash::from_bytes([0x0C; UserHash::BYTE_LEN]));
    conn_tx.send(hello.identified()).await.unwrap();
    conn_tx
        .send(ServeInput::Server(ServerEvent::FileRequested {
            file_hash: FILE,
            status: PartStatusTail::of(&PartBitmap::downloader_empty(SIZE)),
        }))
        .await
        .unwrap();
    conn_tx
        .send(ServeInput::Server(ServerEvent::FileIdSet {
            file_hash: FILE,
        }))
        .await
        .unwrap();

    all_have_had_their_turn().await;
    assert!(
        cmd_rx.try_recv().is_err(),
        "no answer goes from a set nobody has read"
    );

    early.look_ends().await;
    match timeout(Duration::from_secs(5), cmd_rx.recv()).await {
        Ok(Some(ServeOutput::Server(ServerCommand::AnswerFileName { file_hash, .. }))) => {
            assert_eq!(file_hash, FILE);
        }
        other => panic!("the file's name, not {other:?}"),
    }
    match timeout(Duration::from_secs(5), cmd_rx.recv()).await {
        Ok(Some(ServeOutput::Server(ServerCommand::AnswerFileStatus { file_hash, .. }))) => {
            assert_eq!(file_hash, FILE);
        }
        other => panic!("the file's status, not {other:?}"),
    }
    early.stop().await;
}

/// A waiter's ping across our restart: `0x92` for a file we share would cost
/// its download this source (`ClientUDPSocket.cpp:177` answers from the set).
#[tokio::test(start_paused = true)]
async fn a_reask_before_the_look_is_not_told_a_shared_file_is_gone() {
    let mut early = serving_before_the_look();
    let ping = rmule_peer::ReaskFilePing {
        file_hash: FILE,
        part_status: Some(PartBitmap::downloader_empty(SIZE)),
        complete_sources: Some(0),
    }
    .encode_udp();
    early
        .reask_tx
        .send((peer_at([198, 51, 100, 7], 6000), ping))
        .await
        .unwrap();

    all_have_had_their_turn().await;
    assert!(early.client_udp_rx.try_recv().is_err());

    early.look_ends().await;
    all_have_had_their_turn().await;
    assert!(
        early.client_udp_rx.try_recv().is_err(),
        "a stranger with room in the queue meets silence, not file-not-found"
    );
    early.stop().await;
}

/// A share change can trigger a read while the look runs: what it brings is no
/// set, so it cannot let the inputs through.
#[tokio::test]
async fn a_read_before_the_look_ended_is_no_set_at_all() {
    let registry = DurableSharedFileRegistry::new(rmule_testkit::memory_store());
    share_file(&registry);
    let registry = Arc::new(registry);
    let withheld = WithheldRows::before_start_look();
    assert_eq!(
        read_share_set(Arc::clone(&registry), withheld.clone()).await,
        None
    );
    withheld.looked();
    let rows = read_share_set(registry, withheld).await.expect("the set");
    assert_eq!(rows.len(), 1);
}
