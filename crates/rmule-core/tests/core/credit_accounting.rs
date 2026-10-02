//! Download-side byte accounting reaches the shared credit store: the download
//! runner records bytes received from a peer, keyed by its UserHash. (Upload
//! accounting over a real socket is covered in `serve_loopback`.)
use std::sync::Arc;

use rmule_core::DurableCreditStore;
use rmule_core::DurableStore;
use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, CreditStore, DownloadCommand, DownloadEvent,
    DownloadFailure, PeerTransferService, PeerWorker, PeerWorkerCommand, PeerWorkerEvent,
    RuntimeServeRuntimeService, SourceLookupOutcome, SourceLookupService,
};
use rmule_primitives::{
    ClientId, Ed2kFileLink, Ed2kText, ExchangedSource, FileHashSummary, PeerEndpoint, PeerSource,
    ServerEndpoint, SourceLookupTarget, UserHash,
};

const FILE_BYTES: usize = 4096; // sub-part file: one block, one BlockReceived

#[derive(Clone)]
struct OneSourceLookup {
    peer: PeerSource,
}
impl SourceLookupService for OneSourceLookup {
    async fn lookup_sources(
        &mut self,
        _target: SourceLookupTarget,
    ) -> Result<SourceLookupOutcome, DownloadFailure> {
        Ok(SourceLookupOutcome {
            client_id: ClientId::from_u32(0x0100_007F),
            sources: vec![ExchangedSource::plain(self.peer)],
        })
    }
}

struct CreditingPeerTransfer {
    bytes: Vec<u8>,
    user_hash: UserHash,
    /// When set, the worker also reports a completed Secure User
    /// Identification with this public key (ADR-0041).
    verified_key: Option<Vec<u8>>,
}
impl PeerTransferService for CreditingPeerTransfer {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: rmule_peer::PeerHandshakeContext,
        _file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(8);
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);
        let bytes = self.bytes.clone();
        let user_hash = self.user_hash;
        let verified_key = self.verified_key.clone();
        tokio::spawn(async move {
            let _ = event_tx
                .send(PeerWorkerEvent::Identified {
                    user_hash,
                    crypt: Some(rmule_primitives::CryptStance::disabled()),
                    software: nameless_software(),
                })
                .await;
            let _ = event_tx.send(PeerWorkerEvent::Connected).await;
            if let Some(public_key) = verified_key {
                let _ = event_tx
                    .send(PeerWorkerEvent::IdentityVerified {
                        user_hash,
                        public_key,
                    })
                    .await;
            }
            while let Some(command) = command_rx.recv().await {
                match command {
                    PeerWorkerCommand::RequestPart {
                        plan,
                        resume_offset,
                    } => {
                        let start =
                            (resume_offset.saturating_sub(plan.offset) as usize).min(bytes.len());
                        let _ = event_tx
                            .send(PeerWorkerEvent::BlockReceived {
                                part_index: plan.part_index,
                                offset: resume_offset,
                                bytes: bytes[start..].to_vec(),
                            })
                            .await;
                        let _ = event_tx
                            .send(PeerWorkerEvent::PartStreamed {
                                part_index: plan.part_index,
                            })
                            .await;
                    }
                    PeerWorkerCommand::RequestAich { .. } => {}
                    PeerWorkerCommand::RequestAichFileHash => {}
                    PeerWorkerCommand::Shutdown { .. } => break,
                }
            }
        });
        Ok(PeerWorker::new(peer, command_tx, event_rx))
    }
}

/// Run one whole sub-part download from `user_hash` through a scripted worker
/// against the credit ledger of `store`, returning every `CoreEvent` up to (and including) the
/// completion. `verified_key` scripts a completed SUI exchange (ADR-0041).
async fn run_credited_download(
    store: Arc<DurableStore>,
    user_hash: UserHash,
    verified_key: Option<Vec<u8>>,
) -> Vec<CoreEvent> {
    let bytes = vec![0x5A_u8; FILE_BYTES];
    let summary = FileHashSummary::digest_bytes(&bytes);
    let source = PeerSource::new(ClientId::from_u32(0x0200_007F), 5000);

    let mut core = Core::builder(CoreConfig::default(), store)
        .source_lookup(OneSourceLookup { peer: source })
        .peer_transfer(CreditingPeerTransfer {
            bytes,
            user_hash,
            verified_key,
        })
        .serve_runtime(RuntimeServeRuntimeService::new())
        .build();

    let file = Ed2kFileLink {
        name: Ed2kText::from_utf8("credited.bin"),
        size: FILE_BYTES as u64,
        file_hash: summary.file_hash(),
        part_hash_set: None,
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    };
    let output_dir = tempfile::tempdir().expect("temp dir");
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        credentials: rmule_testkit::test_identity(0x01, "rmule", 4662).into(),
        output_path: output_dir.path().join("credited.bin"),
    }))
    .await
    .unwrap();

    // Drain events until the download completes.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut events = Vec::new();
        while let Some(event) = core.next_event().await {
            let done = matches!(
                event,
                CoreEvent::Download(DownloadEvent::DownloadCompleted { .. })
            );
            events.push(event);
            if done {
                return events;
            }
        }
        events
    })
    .await
    .expect("download completed within 5s")
}

#[tokio::test]
async fn download_records_received_bytes_in_the_credit_store() {
    let user_hash = UserHash::from_bytes([0x33; UserHash::BYTE_LEN]);
    let store = rmule_testkit::memory_store();
    let credit = DurableCreditStore::new(store.clone());

    run_credited_download(store.clone(), user_hash, None).await;

    assert_eq!(
        credit.totals(user_hash).unwrap().downloaded,
        FILE_BYTES as u64
    );
    assert_eq!(credit.totals(user_hash).unwrap().uploaded, 0);
}

/// A worker-reported completed SUI exchange binds the peer's public key in the
/// credit store: the peer becomes a **Secured Identity** (ADR-0041).
#[tokio::test]
async fn a_verified_identity_binds_the_peers_public_key_as_secured() {
    let user_hash = UserHash::from_bytes([0x33; UserHash::BYTE_LEN]);
    let store = rmule_testkit::memory_store();
    let credit = DurableCreditStore::new(store.clone());

    run_credited_download(
        store.clone(),
        user_hash,
        Some(b"peer-public-key-der".to_vec()),
    )
    .await;

    assert_eq!(
        credit.public_key(user_hash).unwrap().as_deref(),
        Some(b"peer-public-key-der".as_slice()),
        "the verified key is bound as the peer's Secured Identity"
    );
}

/// A verified exchange under a *different* key than the stored Secured
/// Identity is identity theft (eMule `IS_IDFAILED`): the stored key is never
/// overwritten, the theft is reported, and unsecured byte accrual continues
/// untouched (ADR-0041).
#[tokio::test]
async fn a_mismatched_key_never_rebinds_and_reports_the_theft() {
    let user_hash = UserHash::from_bytes([0x33; UserHash::BYTE_LEN]);
    let store = rmule_testkit::memory_store();
    let credit = DurableCreditStore::new(store.clone());
    credit
        .bind_public_key(user_hash, b"the-original-owner-key")
        .unwrap();

    let events =
        run_credited_download(store.clone(), user_hash, Some(b"the-thiefs-key".to_vec())).await;

    assert_eq!(
        credit.public_key(user_hash).unwrap().as_deref(),
        Some(b"the-original-owner-key".as_slice()),
        "a mismatched key must never overwrite the Secured Identity"
    );
    assert!(
        events.iter().any(
            |e| matches!(e, CoreEvent::SecuredIdentityMismatch { user_hash: h } if *h == user_hash)
        ),
        "the denied claim is reported as a theft fact"
    );
    assert_eq!(
        credit.totals(user_hash).unwrap().downloaded,
        FILE_BYTES as u64,
        "unsecured accrual is untouched by the denial"
    );
}

/// The identification a hello naming no user yields — the fake worker has
/// no hello, and credit accounting reads none.
fn nameless_software() -> rmule_peer::ClientSoftware {
    rmule_peer::ClientSoftware::from_hello_body(&rmule_peer::PeerHelloBody {
        user_hash: rmule_primitives::UserHash::from_bytes([0; 16]),
        client_id: rmule_primitives::ClientId::from_u32(0),
        tcp_port: 0,
        tags: Vec::new(),
        connected_server: rmule_primitives::Ipv4Endpoint::new(std::net::Ipv4Addr::UNSPECIFIED, 0),
    })
}
