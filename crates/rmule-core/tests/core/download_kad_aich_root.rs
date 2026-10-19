//! A download started from a search row with a **Qualified Kad Root** trusts
//! it from the start (ADR-0038): the command carries the root into the
//! download's record, the run starts under it, and the part that fails its
//! check asks its writer for recovery data against it. A link's `h=` ranks
//! above it.

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

/// Serves `bytes` corrupt and reports the root each recovery ask quotes.
struct CorruptingPeer {
    bytes: Vec<u8>,
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
        let (command_tx, mut command_rx) = mpsc::channel(8);
        let (event_tx, event_rx) = mpsc::channel(16);
        tokio::spawn(async move {
            let _ = event_tx.send(PeerWorkerEvent::Connected).await;
            let _ = event_tx.send(rmule_testkit::every_part(file.size)).await;
            while let Some(command) = command_rx.recv().await {
                match command {
                    PeerWorkerCommand::AskSlot | PeerWorkerCommand::TakeGrant => {
                        let _ = event_tx.send(PeerWorkerEvent::SlotGranted).await;
                    }
                    PeerWorkerCommand::RequestBlocks { blocks, handout } => {
                        rmule_testkit::emit_blocks(&event_tx, &parts, &blocks, handout).await;
                    }
                    PeerWorkerCommand::RequestAich { root, .. } => {
                        let _ = asked.send(root);
                    }
                    PeerWorkerCommand::RequestHashSet | PeerWorkerCommand::RequestAichFileHash => {}
                    PeerWorkerCommand::Shutdown { .. } => break,
                }
            }
        });
        Ok(PeerWorker::new(peer, command_tx, event_rx))
    }
}

/// The root a failed part's recovery ask quotes, for a download whose link
/// carries `link_root` as `h=`, started from a row carrying `kad_root`.
async fn root_the_recovery_asks_against(
    link_root: Option<AichRootHash>,
    kad_root: Option<AichRootHash>,
) -> AichRootHash {
    let dir = tempfile::tempdir().unwrap();
    let bytes = b"a part a Kad root recovers".to_vec();
    let file = Ed2kFileLink {
        aich_root: link_root,
        ..file_link_without_part_hash_set("rooted.bin", &bytes)
    };
    let (asked, mut asks) = mpsc::unbounded_channel();
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            dir.path(),
        ))
        .source_lookup(source_with_high_id())
        .peer_transfer(CorruptingPeer { bytes, asked })
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

    timeout(HANG_GUARD, async {
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
        root_the_recovery_asks_against(None, Some(KAD_ROOT)).await,
        KAD_ROOT
    );
}

#[tokio::test]
async fn a_links_root_beats_a_kad_root() {
    assert_eq!(
        root_the_recovery_asks_against(Some(LINK_ROOT), Some(KAD_ROOT)).await,
        LINK_ROOT
    );
}
