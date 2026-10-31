//! A download started from a search row with a **Qualified Kad Root** trusts
//! it from the start (ADR-0038): the command carries the root into the
//! download's record, the run starts under it, and the part that fails its
//! check asks its writer for recovery data against it. A link's `h=` ranks
//! above it.
//!
//! A recovery ask goes to a peer stating the trusted root
//! (3.1.0 `PartFile.cpp:3998-4000`), past the peer's clock: 3.1.0 scores it as
//! an ask (`ClientTCPSocket.cpp:1768`). So the writer states the root and
//! queues the slot ask past that clock, the test's clock jumping the wait,
//! before it grants.

use std::time::Duration;

use rmule_core::{
    Core, CoreCommand, CoreConfig, DownloadCommand, DownloadFailure, DownloadedPart, NameTaken,
    PeerTransferService, PeerWorker, PeerWorkerCommand, PeerWorkerEvent,
};
use rmule_peer::PeerHandshakeContext;
use rmule_primitives::{AichRootHash, Ed2kFileLink, PeerEndpoint, ServerEndpoint};
use rmule_testkit::HANG_GUARD;
use rmule_testkit::{file_link_without_part_hash_set, source_with_high_id};
use tokio::sync::mpsc;
use tokio::time::timeout;

const LINK_ROOT: AichRootHash = AichRootHash::from_bytes([0x11; AichRootHash::BYTE_LEN]);
const KAD_ROOT: AichRootHash = AichRootHash::from_bytes([0xA1; AichRootHash::BYTE_LEN]);

/// How long the writer queues the slot ask: past aMule's `MIN_REQUESTTIME`
/// (`Constants.h:67`, 590 s).
const QUEUED_FOR: Duration = Duration::from_secs(600);

/// States `root`, queues the slot ask for [`QUEUED_FOR`], serves `bytes`
/// corrupt and reports the root each recovery ask quotes.
struct CorruptingPeer {
    bytes: Vec<u8>,
    root: AichRootHash,
    asked: mpsc::UnboundedSender<AichRootHash>,
}

impl PeerTransferService for CorruptingPeer {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        let mut corrupt = self.bytes.clone();
        corrupt[0] ^= 0xFF;
        let parts = vec![DownloadedPart {
            part_index: 0,
            offset: 0,
            bytes: corrupt,
        }];
        let asked = self.asked.clone();
        let root = self.root;
        let (command_tx, mut command_rx) = mpsc::channel(8);
        let (event_tx, event_rx) = mpsc::channel(16);
        tokio::spawn(async move {
            let _ = event_tx.send(PeerWorkerEvent::Connected).await;
            let _ = event_tx.send(rmule_testkit::every_part(file.size)).await;
            while let Some(command) = command_rx.recv().await {
                match command {
                    PeerWorkerCommand::AskSlot | PeerWorkerCommand::TakeGrant => {
                        tokio::time::pause();
                        tokio::time::advance(QUEUED_FOR).await;
                        tokio::time::resume();
                        let _ = event_tx.send(PeerWorkerEvent::SlotGranted).await;
                    }
                    PeerWorkerCommand::RequestBlocks { blocks, handout } => {
                        rmule_testkit::emit_blocks(&event_tx, &parts, &blocks, handout).await;
                    }
                    PeerWorkerCommand::RequestAich { root, .. } => {
                        let _ = asked.send(root);
                    }
                    PeerWorkerCommand::RequestAichFileHash => {
                        let answer = PeerWorkerEvent::AichFileHashReceived { root };
                        let _ = event_tx.send(answer).await;
                    }
                    PeerWorkerCommand::RequestHashSet => {}
                    PeerWorkerCommand::Shutdown { .. } => break,
                }
            }
        });
        Ok(PeerWorker::new(peer, command_tx, event_rx))
    }
}

/// The root a failed part's recovery ask quotes, for a download whose link
/// carries `link_root` as `h=`, started from a row carrying `kad_root`, its
/// one peer stating `stated`. A peer stating any other root is asked nothing.
async fn root_the_recovery_asks_against(
    link_root: Option<AichRootHash>,
    kad_root: Option<AichRootHash>,
    stated: AichRootHash,
) -> AichRootHash {
    let dir = tempfile::tempdir().unwrap();
    let bytes = b"a part a Kad root recovers".to_vec();
    let file = Ed2kFileLink {
        aich_root: link_root,
        ..file_link_without_part_hash_set("rooted.bin", &bytes)
    };
    let (asked, mut asks) = mpsc::unbounded_channel();
    let config = CoreConfig {
        slot_wait_timeout: QUEUED_FOR * 2,
        ..CoreConfig::default()
    };
    let mut core = Core::builder(config, rmule_testkit::memory_store())
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            dir.path(),
        ))
        .source_lookup(source_with_high_id())
        .peer_transfer(CorruptingPeer {
            bytes,
            root: stated,
            asked,
        })
        .build();
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        name: rmule_testkit::file_name("rooted.bin"),
        if_taken: NameTaken::Refuse,
        kad_aich_root: kad_root,
    }))
    .await
    .unwrap();

    timeout(QUEUED_FOR + HANG_GUARD, async {
        loop {
            tokio::select! {
                root = asks.recv() => return root.expect("the peer stays up"),
                event = core.next_event() => {
                    event.expect("core alive");
                }
            }
        }
    })
    .await
    .expect("the failed part asked for recovery data")
}

#[tokio::test]
async fn a_download_started_with_a_kad_root_recovers_against_it() {
    assert_eq!(
        root_the_recovery_asks_against(None, Some(KAD_ROOT), KAD_ROOT).await,
        KAD_ROOT
    );
}

#[tokio::test]
async fn a_links_root_beats_a_kad_root() {
    assert_eq!(
        root_the_recovery_asks_against(Some(LINK_ROOT), Some(KAD_ROOT), LINK_ROOT).await,
        LINK_ROOT
    );
}
