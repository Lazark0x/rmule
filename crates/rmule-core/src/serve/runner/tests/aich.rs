//! A shared file's AICH tree built by the serve task from the file on disk,
//! one block at a time (ADR-0038, ADR-0031): the root it answers is the root
//! of the file's bytes.

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
        Ok(Some(ServeOutput::Server(ServerCommand::AnswerAichFileHash { root }))) => {
            assert_eq!(root, AichHashSet::from_bytes(&bytes).master_root());
        }
        other => panic!("the file's AICH root, not {other:?}"),
    }

    let _ = stop_tx.send(true);
    let _ = serve.await;
}
