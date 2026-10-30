//! A link to one endpoint and the link that follows it there: the loop keys
//! its links by endpoint, so the second is not taken on until the first's close
//! is folded, whichever of the two the loop reads first.

use super::*;
use crate::adapters::LinkServeHalf;
use crate::served_downloads::leased::{Leased, leased};

/// One link's far ends, as the dial that made it hands them to the loop.
struct Dialed {
    commands: mpsc::Receiver<ServeOutput>,
    events: mpsc::Sender<ServeInput>,
}

fn dialed(peer: PeerEndpoint) -> (Dialed, LinkServeHalf) {
    let (cmd_tx, commands) = mpsc::channel(16);
    let (events, conn_rx) = mpsc::channel(16);
    let half = LinkServeHalf {
        conn: ServeConnection::new(peer, cmd_tx, conn_rx),
        dialed: None,
    };
    (Dialed { commands, events }, half)
}

impl Dialed {
    /// The link says its hello and asks for `file`; the status answer proves
    /// the loop holds it.
    async fn is_served(&mut self, file: FileHash) {
        let hello = HelloFacts::of(UserHash::from_bytes([0x0C; UserHash::BYTE_LEN]));
        self.events.send(hello.identified()).await.unwrap();
        self.events
            .send(ServeInput::Server(ServerEvent::FileIdSet {
                file_hash: file,
            }))
            .await
            .unwrap();
        match timeout(Duration::from_secs(5), self.commands.recv()).await {
            Ok(Some(ServeOutput::Server(ServerCommand::AnswerFileStatus { .. }))) => {}
            other => panic!("a status answer, not {other:?}"),
        }
    }
}

/// The current-thread runtime reads both inputs in the one wake: the loop
/// takes the new link first, the old link's close being behind it.
#[tokio::test]
async fn a_redial_read_ahead_of_the_old_links_close_is_served() {
    let file = FileHash::from_bytes([0x23; FileHash::BYTE_LEN]);
    let Leased { store, cell, .. } = leased(file, "/downloads/download.bin".into());
    let (_accept_tx, accept_rx) = mpsc::channel::<ServeConnection>(8);
    let (dialed_tx, dialed_rx) = mpsc::channel(8);
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
            dialed_serve_rx: Some(dialed_rx),
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
            served: cell,
        }
        .run(),
    );
    next_serve_event(&mut evt_rx, |e| {
        matches!(e, ServeEvent::FilesAnnounced { .. })
    })
    .await;

    let peer = peer_at([203, 0, 113, 8], 4662);
    let (mut old, half) = dialed(peer);
    dialed_tx.send(half).await.unwrap();
    old.is_served(file).await;

    let (mut new, half) = dialed(peer);
    old.events.send(ServeInput::closed_here()).await.unwrap();
    dialed_tx.send(half).await.unwrap();

    new.is_served(file).await;

    let _ = stop_tx.send(true);
    let _ = serve.await;
}
