//! A shared file's AICH tree built by the serve task from the file on disk,
//! one block at a time, away from the serve loop (ADR-0038, ADR-0031): the
//! root it answers is the root of the file's bytes, and a build that takes as
//! long as it likes holds no other peer up.

use super::*;
use rmule_primitives::{AichHashSet, EMBLOCKSIZE};

#[tokio::test]
async fn an_aich_root_ask_is_answered_from_the_tree_read_off_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("shared.bin");
    // Past two blocks, so the tree has a short last leaf.
    let bytes: Vec<u8> = (0..2 * EMBLOCKSIZE + 5).map(|i| (i % 251) as u8).collect();
    std::fs::write(&path, &bytes).unwrap();
    let file = FileHash::from_bytes([0x33; FileHash::BYTE_LEN]);
    let store = rmule_testkit::memory_store();
    let registry = DurableSharedFileRegistry::new(store.clone());
    registry
        .share(SharedFileEntry {
            file_hash: file,
            file_size: bytes.len() as u64,
            path,
            name: "shared.bin".into(),
            source: ShareSource::Explicit,
            modified: None,
            part_hashes: Vec::new(),
        })
        .unwrap();

    let (accept_tx, accept_rx) = mpsc::channel::<ServeConnection>(4);
    let (evt_tx, mut evt_rx) = mpsc::channel::<CoreEvent>(64);
    let (stop_tx, stop_rx) = watch::channel(false);
    let (_share_changed_tx, share_changed_rx) = mpsc::channel::<()>(1);
    let serve = tokio::spawn(
        ServeTask {
            bans: Default::default(),
            registry: Arc::new(registry),
            serve_runtime: FakeServeRuntime {
                bound: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4662),
                accepts: accept_rx,
            },
            queue: UploadSlotQueue::new(1, 8),
            own_identity: None,
            evt_tx,
            stop_rx,
            share_changed_rx,
            dialed_serve_rx: None,
            credit: Arc::new(DurableCreditStore::new(store)),
            held_places: crate::held_places::SharedHeldPlaces::default(),
            rerank_interval: Duration::from_secs(3600),
            reask_rx: None,
            client_udp_tx: None,
            purge_interval: Duration::from_secs(3600),
            purge_after: Duration::from_secs(3600),
            diagnostics: crate::diagnostics::DiagnosticsState::new(),
            peer_roster: crate::peer_roster::SharedPeerRoster::default(),
            withheld: crate::registry_check::WithheldRows::default(),
            read_failed_tx: None,
            served: Default::default(),
        }
        .run(),
    );
    next_serve_event(&mut evt_rx, |e| {
        matches!(e, ServeEvent::FilesAnnounced { .. })
    })
    .await;

    let asker = peer_at([198, 51, 100, 3], 4000);
    let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
    let (conn_tx, conn_rx) = mpsc::channel(16);
    accept_tx
        .send(ServeConnection::new(asker, cmd_tx, conn_rx))
        .await
        .unwrap();
    let hello = HelloFacts::of(UserHash::from_bytes([0x0D; UserHash::BYTE_LEN]));
    conn_tx.send(hello.identified()).await.unwrap();
    conn_tx
        .send(ServeInput::Server(ServerEvent::AichFileHashRequested {
            file_hash: file,
        }))
        .await
        .unwrap();

    match timeout(Duration::from_secs(5), cmd_rx.recv()).await {
        Ok(Some(ServeOutput::Server(ServerCommand::AnswerAichFileHash { file_hash, root }))) => {
            assert_eq!(file_hash, file);
            assert_eq!(root, AichHashSet::from_bytes(&bytes).master_root());
        }
        other => panic!("the file's AICH root, not {other:?}"),
    }

    let _ = stop_tx.send(true);
    let _ = serve.await;
}

/// One shared file, named after `seed`.
pub(super) fn shared(
    registry: &DurableSharedFileRegistry,
    seed: u8,
    size: u64,
    path: std::path::PathBuf,
) -> FileHash {
    let file_hash = FileHash::from_bytes([seed; FileHash::BYTE_LEN]);
    registry
        .share(SharedFileEntry {
            file_hash,
            file_size: size,
            path,
            name: format!("{seed}.bin").as_str().into(),
            source: ShareSource::Explicit,
            modified: None,
            part_hashes: Vec::new(),
        })
        .unwrap();
    file_hash
}

/// A serve task over `registry`, its share set announced.
pub(super) async fn serving(
    registry: DurableSharedFileRegistry,
    store: Arc<rmule_store::Store>,
) -> ServeRig {
    let (accept_tx, accept_rx) = mpsc::channel::<ServeConnection>(4);
    let (evt_tx, mut evt_rx) = mpsc::channel::<CoreEvent>(64);
    let (stop_tx, stop_rx) = watch::channel(false);
    let (share_changed_tx, share_changed_rx) = mpsc::channel::<()>(1);
    let task = tokio::spawn(
        ServeTask {
            bans: Default::default(),
            registry: Arc::new(registry),
            serve_runtime: FakeServeRuntime {
                bound: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4662),
                accepts: accept_rx,
            },
            queue: UploadSlotQueue::new(1, 8),
            own_identity: None,
            evt_tx,
            stop_rx,
            share_changed_rx,
            dialed_serve_rx: None,
            credit: Arc::new(DurableCreditStore::new(store)),
            held_places: crate::held_places::SharedHeldPlaces::default(),
            rerank_interval: Duration::from_secs(3600),
            reask_rx: None,
            client_udp_tx: None,
            purge_interval: Duration::from_secs(3600),
            purge_after: Duration::from_secs(3600),
            diagnostics: crate::diagnostics::DiagnosticsState::new(),
            peer_roster: crate::peer_roster::SharedPeerRoster::default(),
            withheld: crate::registry_check::WithheldRows::default(),
            read_failed_tx: None,
            served: Default::default(),
        }
        .run(),
    );
    next_serve_event(&mut evt_rx, |e| {
        matches!(e, ServeEvent::FilesAnnounced { .. })
    })
    .await;
    ServeRig {
        accept_tx,
        _events: evt_rx,
        stop_tx,
        _share_changed_tx: share_changed_tx,
        task,
    }
}

/// A serve task, and what keeps it running.
pub(super) struct ServeRig {
    accept_tx: mpsc::Sender<ServeConnection>,
    _events: mpsc::Receiver<CoreEvent>,
    stop_tx: watch::Sender<bool>,
    _share_changed_tx: mpsc::Sender<()>,
    task: tokio::task::JoinHandle<crate::serve::ServeOutcome<FakeServeRuntime>>,
}

impl ServeRig {
    /// Accept a connection from `peer`: what it says, and what it is told.
    pub(super) async fn link(
        &self,
        peer: PeerEndpoint,
    ) -> (mpsc::Sender<ServeInput>, mpsc::Receiver<ServeOutput>) {
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let (conn_tx, conn_rx) = mpsc::channel(16);
        self.accept_tx
            .send(ServeConnection::new(peer, cmd_tx, conn_rx))
            .await
            .unwrap();
        (conn_tx, cmd_rx)
    }

    pub(super) async fn stop(self) {
        let _ = self.stop_tx.send(true);
        let _ = self.task.await;
    }
}

/// The next thing the serve task says down one connection, or the test ends:
/// the bound only fails a loop that never answers, nothing here waits it out.
pub(super) async fn said(rx: &mut mpsc::Receiver<ServeOutput>, what: &str) -> ServerCommand {
    match timeout(Duration::from_secs(5), rx.recv()).await {
        Ok(Some(ServeOutput::Server(command))) => command,
        other => panic!("{what}, not {other:?}"),
    }
}

/// The file behind the build is a pipe, so the build parks on its first read
/// until the test writes, however fast this machine is. While it is parked the
/// asker and another peer are answered and a slot serves a block; the bytes
/// then land the tree, and the asker gets its root.
#[cfg(unix)]
#[tokio::test]
async fn a_build_stuck_on_its_file_holds_no_other_peer_up() {
    use std::io::Write as _;

    let dir = tempfile::tempdir().unwrap();
    let pipe = dir.path().join("slow.bin");
    let mut pipe_end = crate::serve::aich_builder::parked_file(&pipe);
    let slow_bytes: Vec<u8> = (0..2 * EMBLOCKSIZE + 5).map(|i| (i % 251) as u8).collect();
    let ready_path = dir.path().join("ready.bin");
    std::fs::write(&ready_path, vec![7u8; 4096]).unwrap();

    let store = rmule_testkit::memory_store();
    let registry = DurableSharedFileRegistry::new(store.clone());
    let slow = shared(&registry, 0x41, slow_bytes.len() as u64, pipe);
    let ready = shared(&registry, 0x42, 4096, ready_path);

    let rig = serving(registry, store).await;

    let asker = peer_at([198, 51, 100, 3], 4000);
    let (asker_conn, mut asker_rx) = rig.link(asker).await;
    let other = peer_at([198, 51, 100, 4], 4000);
    let (other_conn, mut other_rx) = rig.link(other).await;
    let hello = HelloFacts::of(UserHash::from_bytes([0x0D; UserHash::BYTE_LEN]));
    asker_conn.send(hello.identified()).await.unwrap();
    let hello = HelloFacts::of(UserHash::from_bytes([0x0E; UserHash::BYTE_LEN]));
    other_conn.send(hello.identified()).await.unwrap();

    // One connection keeps its order, so the ask below follows the root ask
    // into the serve loop: on a loop waiting for the build it is never read.
    asker_conn
        .send(ServeInput::Server(ServerEvent::AichFileHashRequested {
            file_hash: slow,
        }))
        .await
        .unwrap();
    let status_ask = ServeInput::Server(ServerEvent::FileIdSet { file_hash: ready });
    asker_conn.send(status_ask.clone()).await.unwrap();
    assert!(matches!(
        said(&mut asker_rx, "the asker's next ask answered").await,
        ServerCommand::AnswerFileStatus { .. }
    ));

    other_conn.send(status_ask).await.unwrap();
    assert!(matches!(
        said(&mut other_rx, "another peer's ask answered").await,
        ServerCommand::AnswerFileStatus { .. }
    ));
    other_conn
        .send(ServeInput::Server(ServerEvent::SlotRequested {
            file_hash: ready,
        }))
        .await
        .unwrap();
    assert!(matches!(
        said(&mut other_rx, "a slot granted").await,
        ServerCommand::GrantSlot { .. }
    ));
    other_conn
        .send(ServeInput::Server(ServerEvent::PartsRequested {
            file_hash: ready,
            ranges: rmule_peer::PartRanges::new([(0, 100), (0, 0), (0, 0)]),
        }))
        .await
        .unwrap();
    assert!(matches!(
        said(&mut other_rx, "a block served").await,
        ServerCommand::SendBlock { .. }
    ));

    pipe_end.write_all(&slow_bytes).unwrap();
    match said(&mut asker_rx, "the root, once the tree lands").await {
        ServerCommand::AnswerAichFileHash { root, .. } => {
            assert_eq!(root, AichHashSet::from_bytes(&slow_bytes).master_root());
        }
        other => panic!("the file's AICH root, not {other:?}"),
    }

    rig.stop().await;
}
