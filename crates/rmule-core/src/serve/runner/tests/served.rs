//! The serve task reads the **Served Downloads** afresh before each peer
//! input (ADR-0113 rule 5) and hands a running download's asker to its run.

use super::*;
use crate::served_downloads::leased::{Leased, SIZE, leased};
use rmule_peer::{PartBitmap, PartStatusTail};
use rmule_primitives::ED2K_PART_SIZE;

#[tokio::test]
async fn a_part_a_run_just_verified_is_answered_on_the_next_ask_and_the_asker_reaches_the_run() {
    let file = FileHash::from_bytes([0x22; FileHash::BYTE_LEN]);
    let Leased {
        store,
        cell,
        lease,
        set,
        ..
    } = leased(file, "/downloads/download.bin".into());
    let mut askers = lease.take_askers().unwrap();

    let (accept_tx, accept_rx) = mpsc::channel::<ServeConnection>(8);
    let (evt_tx, mut evt_rx) = mpsc::channel::<CoreEvent>(64);
    let (stop_tx, stop_rx) = watch::channel(false);
    let (_share_changed_tx, share_changed_rx) = mpsc::channel::<()>(1);
    let serve = tokio::spawn(
        ServeTask {
            bans: Default::default(),
            registry: Arc::new(DurableSharedFileRegistry::new(store.clone())),
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
            served: cell.clone(),
        }
        .run(),
    );
    next_serve_event(&mut evt_rx, |e| {
        matches!(e, ServeEvent::FilesAnnounced { .. })
    })
    .await;

    let peer = peer_at([203, 0, 113, 7], 4000);
    let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
    let (conn_tx, conn_rx) = mpsc::channel(16);
    accept_tx
        .send(ServeConnection::new(peer, cmd_tx, conn_rx))
        .await
        .unwrap();
    let hello = || HelloFacts::of(UserHash::from_bytes([0x0B; UserHash::BYTE_LEN]));
    let sighting = hello().identity().source_coordinate(peer);
    conn_tx.send(hello().identified()).await.unwrap();
    let mut status = async || {
        conn_tx
            .send(ServeInput::Server(ServerEvent::FileIdSet {
                file_hash: file,
            }))
            .await
            .unwrap();
        match timeout(Duration::from_secs(5), cmd_rx.recv()).await {
            Ok(Some(ServeOutput::Server(ServerCommand::AnswerFileStatus { bitmap, .. }))) => bitmap,
            other => panic!("a status answer, not {other:?}"),
        }
    };
    assert_eq!(status().await, PartBitmap::downloader_empty(SIZE));

    lease.record_range(
        &set,
        &[crate::VerifiedPartRecord {
            part_index: 1,
            offset: ED2K_PART_SIZE,
            len: ED2K_PART_SIZE,
            part_hash: set[1],
        }],
    );
    assert_eq!(
        status().await,
        PartBitmap::downloader(SIZE, |part| part.value() == 1),
        "the part the run verified, on the very next ask"
    );

    conn_tx
        .send(ServeInput::Server(ServerEvent::FileRequested {
            file_hash: file,
            status: PartStatusTail::of(&PartBitmap::downloader_empty(SIZE)),
        }))
        .await
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(5), askers.recv()).await,
        Ok(Some(sighting)),
        "the asker reached the run"
    );

    let _ = stop_tx.send(true);
    let _ = serve.await;
}
