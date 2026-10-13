//! The serve task reads a Partial Share's bytes from real files (ADR-0113
//! §"Reading a part file"): through a handle proven to be the file its
//! Verified Range was read from — the key always, the length and time only
//! while no run writes it — from the final path when the completion move put
//! the bytes there, and never through the Registry Check.

use std::path::PathBuf;
use std::time::SystemTime;

use super::*;
use crate::VerifiedPartRecord;
use crate::file_key::FileKey;
use crate::registry_check::CheckInput;
use crate::served_downloads::leased::{Leased, SIZE, leased};
use crate::served_downloads::{PartFileIdentity, PartialEnd, RunLease, ServedDownloads};
use rmule_peer::PartRanges;
use rmule_primitives::ED2K_PART_SIZE;

/// A serve task offering one download's first part from a part file in a
/// temp dir, and one granted peer asking it for blocks.
struct Rig {
    _dir: tempfile::TempDir,
    file: FileHash,
    part: PathBuf,
    done: PathBuf,
    cell: ServedDownloads,
    _lease: RunLease,
    conn_tx: mpsc::Sender<ServeInput>,
    /// How many blocks were asked for, so each ask names bytes not yet
    /// served.
    asked: u64,
    cmd_rx: mpsc::Receiver<ServeOutput>,
    read_failed_rx: std::sync::mpsc::Receiver<CheckInput>,
    stop_tx: watch::Sender<bool>,
    /// Held: a closed trigger ends the task.
    _share_changed_tx: mpsc::Sender<()>,
    serve: tokio::task::JoinHandle<crate::serve::runner::ServeOutcome<FakeServeRuntime>>,
}

/// The rig over a download whose run is writing its part file, or — when
/// `paused` — whose run let it go, handing the entry back to the actor.
async fn rig(paused: bool) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let file = FileHash::from_bytes([0x33; FileHash::BYTE_LEN]);
    let Leased {
        store,
        record,
        cell,
        lease,
        set,
    } = leased(file, dir.path().join("download.bin"));
    let (part, done) = (
        record.paths().part_path().to_path_buf(),
        record.paths().final_path().to_path_buf(),
    );
    std::fs::write(&part, vec![0xA7; SIZE as usize]).unwrap();
    let held = std::fs::File::open(&part).unwrap();
    let key = FileKey::of_open(&held).unwrap();
    let identity = if paused {
        PartFileIdentity::at_rest(key, &held.metadata().unwrap()).unwrap()
    } else {
        PartFileIdentity::while_written(key)
    };
    lease.record_identity(identity);
    lease.record_range(
        &set,
        &[VerifiedPartRecord {
            part_index: 0,
            offset: 0,
            len: ED2K_PART_SIZE,
            part_hash: set[0],
        }],
    );
    if paused {
        cell.take_back(file, crate::download::RunNumber::new(1));
    }
    cell.look();

    let (accept_tx, accept_rx) = mpsc::channel::<ServeConnection>(8);
    let (evt_tx, mut evt_rx) = mpsc::channel::<CoreEvent>(64);
    let (stop_tx, stop_rx) = watch::channel(false);
    let (share_changed_tx, share_changed_rx) = mpsc::channel::<()>(1);
    let (read_failed_tx, read_failed_rx) = std::sync::mpsc::channel();
    let serve = tokio::spawn(
        ServeTask {
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
            rerank_interval: Duration::from_secs(3600),
            reask_rx: None,
            client_udp_tx: None,
            purge_interval: Duration::from_secs(3600),
            purge_after: Duration::from_secs(3600),
            diagnostics: crate::diagnostics::DiagnosticsState::new(),
            peer_roster: crate::peer_roster::SharedPeerRoster::default(),
            withheld: crate::registry_check::WithheldRows::default(),
            read_failed_tx: Some(read_failed_tx),
            served: cell.clone(),
        }
        .run(),
    );
    next_serve_event(&mut evt_rx, |e| {
        matches!(e, ServeEvent::FilesAnnounced { file_count: 1 })
    })
    .await;

    let peer = peer_at([203, 0, 113, 9], 4000);
    let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
    let (conn_tx, conn_rx) = mpsc::channel(16);
    accept_tx
        .send(ServeConnection::new(peer, cmd_tx, conn_rx))
        .await
        .unwrap();
    let hello = HelloFacts::of(UserHash::from_bytes([0x0C; UserHash::BYTE_LEN]));
    conn_tx.send(hello.identified()).await.unwrap();
    conn_tx
        .send(ServeInput::Server(ServerEvent::SlotRequested {
            file_hash: file,
        }))
        .await
        .unwrap();
    assert!(matches!(
        next_command(&mut cmd_rx).await,
        ServerCommand::GrantSlot { .. }
    ));
    Rig {
        _dir: dir,
        file,
        part,
        done,
        cell,
        _lease: lease,
        conn_tx,
        asked: 0,
        cmd_rx,
        read_failed_rx,
        stop_tx,
        _share_changed_tx: share_changed_tx,
        serve,
    }
}

async fn next_command(cmd_rx: &mut mpsc::Receiver<ServeOutput>) -> ServerCommand {
    match timeout(Duration::from_secs(5), cmd_rx.recv()).await {
        Ok(Some(ServeOutput::Server(command))) => command,
        other => panic!("a command to the peer, not {other:?}"),
    }
}

impl Rig {
    /// Ask for the next hundred bytes of the first part and return what the
    /// peer is sent first.
    async fn ask_block(&mut self) -> ServerCommand {
        let start = self.asked * 100;
        self.asked += 1;
        self.conn_tx
            .send(ServeInput::Server(ServerEvent::PartsRequested {
                file_hash: self.file,
                ranges: PartRanges::new([(start, start + 100), (0, 0), (0, 0)]).unwrap(),
            }))
            .await
            .unwrap();
        next_command(&mut self.cmd_rx).await
    }

    /// The block was sent, read from the bytes the part file holds.
    async fn served(&mut self) -> bool {
        match self.ask_block().await {
            ServerCommand::SendBlock { bytes, .. } => bytes == [0xA7; 100],
            ServerCommand::AnswerFileNotFound { .. } => false,
            other => panic!("a block or not found, not {other:?}"),
        }
    }

    /// End the task; whether a read reached the Registry Check, and why the
    /// offer was withdrawn, if it was.
    async fn finish(self) -> (bool, Vec<crate::served_downloads::OfferChange>) {
        let _ = self.stop_tx.send(true);
        let _ = self.serve.await;
        (self.read_failed_rx.try_recv().is_ok(), self.cell.look())
    }
}

#[tokio::test]
async fn a_paused_part_file_left_alone_is_served_and_one_replaced_or_touched_sends_nothing() {
    let mut alone = rig(true).await;
    assert!(alone.served().await);
    assert!(alone.served().await, "and keeps serving");
    assert_eq!(alone.finish().await, (false, Vec::new()));

    let mut replaced = rig(true).await;
    let other = replaced.part.with_extension("other");
    std::fs::write(&other, vec![0xA7; SIZE as usize]).unwrap();
    std::fs::rename(&other, &replaced.part).unwrap();
    assert!(!replaced.served().await, "another file sends no byte");
    let file = replaced.file;
    assert_eq!(
        replaced.finish().await,
        (
            false,
            vec![crate::served_downloads::OfferChange::Withdrawn(
                file,
                PartialEnd::Changed
            )]
        ),
        "and the download stops offering its parts"
    );

    let mut touched = rig(true).await;
    std::fs::File::options()
        .write(true)
        .open(&touched.part)
        .unwrap()
        .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(86_400))
        .unwrap();
    assert!(!touched.served().await, "a written file sends no byte");
    assert_eq!(touched.finish().await.1.len(), 1);
}

#[tokio::test]
async fn a_running_downloads_read_checks_only_the_key() {
    let mut running = rig(false).await;
    let mut held = std::fs::File::options()
        .append(true)
        .open(&running.part)
        .unwrap();
    std::io::Write::write_all(&mut held, b"more").unwrap();
    assert!(
        running.served().await,
        "the run moves the length and the time"
    );
    assert_eq!(running.finish().await, (false, Vec::new()));
}

#[tokio::test]
async fn a_read_after_the_move_is_served_from_the_final_path_and_both_gone_ends_serving() {
    let mut moved = rig(false).await;
    std::fs::rename(&moved.part, &moved.done).unwrap();
    assert!(moved.served().await, "read from the final path");

    std::fs::remove_file(&moved.done).unwrap();
    assert_eq!(
        moved.ask_block().await,
        ServerCommand::AnswerFileNotFound {
            file_hash: moved.file
        },
        "neither path holds it: the holder is told"
    );
    let file = moved.file;
    assert_eq!(
        moved.finish().await,
        (
            false,
            vec![crate::served_downloads::OfferChange::Withdrawn(
                file,
                PartialEnd::Unreadable
            )]
        ),
        "never through the Registry Check"
    );
}
