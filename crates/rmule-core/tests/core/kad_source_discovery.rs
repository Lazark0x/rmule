//! Core correctness for the Kad **Source Discovery Policy** channel
//! (ADR-0043): a faked Kad adapter feeds projected sources into a
//! download's candidate pool and the scheduler dials them — no socket, no
//! eD2k server login (the lookup fails and the download waits on Kad).

use rmule_testkit::HANG_GUARD;
use std::time::Duration;

use crate::fixture::{StubKad, kad_enable_config};
use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand, DownloadEvent, DownloadFailure,
    DownloadedPart, PeerDownloadOutcome, PeerTransferService, PeerWorker, PeerWorkerCommand,
    PeerWorkerEvent, SourceLookupOutcome, SourceLookupService,
};
use rmule_peer::PeerHandshakeContext;
use rmule_primitives::{
    ClientId, Ed2kFileLink, Informant, PeerEndpoint, PeerSource, ServerEndpoint,
    SourceLookupTarget, SourceSighting,
};
use rmule_testkit::file_link_without_part_hash_set;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// Server source lookup that always fails: the serverless world. With Kad
/// discovery armed the download must survive this and wait for Kad sources.
#[derive(Clone)]
struct FailingSourceLookup;

impl SourceLookupService for FailingSourceLookup {
    async fn lookup_sources(
        &mut self,
        _target: SourceLookupTarget,
    ) -> Result<SourceLookupOutcome, DownloadFailure> {
        Err(DownloadFailure::ServerDisconnected)
    }
}

/// Serves the whole (single-part) file to the one expected peer, mirroring
/// `fake_orchestration`'s scripted worker.
struct ScriptedPeerTransfer {
    expected_peer: PeerEndpoint,
    outcome: PeerDownloadOutcome,
}

impl PeerTransferService for ScriptedPeerTransfer {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        let advertised = rmule_testkit::every_part(file.size);
        assert_eq!(
            peer, self.expected_peer,
            "the scheduler dials the Kad-fed source"
        );
        let (command_tx, mut command_rx) = mpsc::channel(8);
        let (event_tx, event_rx) = mpsc::channel(16);
        let outcome = self.outcome.clone();
        tokio::spawn(async move {
            let _ = event_tx.send(PeerWorkerEvent::Connected).await;
            let _ = event_tx.send(advertised).await;
            while let Some(command) = command_rx.recv().await {
                match command {
                    PeerWorkerCommand::AskSlot | PeerWorkerCommand::TakeGrant => {
                        let _ = event_tx.send(PeerWorkerEvent::SlotGranted).await;
                    }
                    PeerWorkerCommand::RequestHashSet => {}
                    PeerWorkerCommand::RequestBlocks { blocks, handout } => {
                        rmule_testkit::emit_blocks(&event_tx, &outcome.parts, &blocks, handout)
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

#[tokio::test]
async fn kad_fed_sources_fill_the_pool_and_the_scheduler_dials_them() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = b"kad serverless payload".to_vec();
    let kad_source = PeerSource::new(ClientId::from_u32(u32::from_le_bytes([10, 0, 0, 9])), 4663);
    let peer = kad_source.as_peer_endpoint().unwrap();

    let transfer = ScriptedPeerTransfer {
        expected_peer: peer,
        outcome: PeerDownloadOutcome {
            peer_hashes: Vec::new(),
            parts: vec![DownloadedPart {
                part_index: 0,
                offset: 0,
                bytes: bytes.clone(),
            }],
        },
    };
    let factory =
        StubKad::new().answering_sources(vec![SourceSighting::plain(kad_source, Informant::Own)]);

    let mut core = Core::builder(
        CoreConfig {
            kad_sweep_interval: Duration::from_millis(10),
            ..CoreConfig::default()
        },
        rmule_testkit::memory_store(),
    )
    .settings(rmule_testkit::in_download_dir(
        rmule_core::CoreSettings::default(),
        dir.path(),
    ))
    .source_lookup(FailingSourceLookup)
    .peer_transfer(transfer)
    .kad(factory)
    .build();

    core.send(CoreCommand::EnableKad(kad_enable_config()))
        .await
        .unwrap();

    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: file_link_without_part_hash_set("kad-fed.bin", &bytes),
        // A server nothing listens on: the lookup fails and Kad carries it.
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 1).unwrap()),
        name: rmule_testkit::file_name("kad-fed.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
        kad_aich_root: None,
    }))
    .await
    .unwrap();

    let mut events = Vec::new();
    loop {
        let event = timeout(HANG_GUARD, core.next_event())
            .await
            .expect("core emitted next event")
            .expect("core event stream stayed open");
        let completed = matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. })
        );
        events.push(event);
        if completed {
            break;
        }
    }

    // The failed server lookup degraded to a Kad wait, not a failure.
    assert!(
        events.iter().any(|event| matches!(
            event,
            CoreEvent::Download(DownloadEvent::WaitingForSources { .. })
        )),
        "the sourceless download waits on Kad rather than failing: {events:?}"
    );
    // No server login ever succeeded: the whole loop ran on the Kad channel
    // (the dial itself is asserted inside the scripted transfer adapter; disk
    // bytes are the serverless E2E's job — this store keeps content in memory).
    assert!(
        !events.iter().any(|event| matches!(
            event,
            CoreEvent::Download(DownloadEvent::ServerLoginAccepted { .. })
        )),
        "serverless: no login event must be emitted: {events:?}"
    );
}

/// The Kad-only operator end to end: no server configured, Kad up. A
/// search goes out over Kad, a row it returns starts a download with no
/// source hint, Kad finds its source, and a part is fetched from that peer —
/// nothing ever logs in.
#[tokio::test]
async fn with_no_server_at_all_a_kad_search_row_downloads_over_kad() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = b"kad only operator payload".to_vec();
    let link = file_link_without_part_hash_set("kad-only.bin", &bytes);
    let kad_source = PeerSource::new(ClientId::from_u32(u32::from_le_bytes([10, 0, 0, 11])), 4663);
    let row = rmule_primitives::SearchResult::new(
        link.file_hash,
        link.size,
        vec![link.name.clone()],
        vec![kad_source],
    )
    .expect("a valid row");
    let channel = StubKad::new()
        .answering_sources(vec![SourceSighting::plain(kad_source, Informant::Own)])
        .answering_keywords(vec![row]);
    let mut core = Core::builder(
        CoreConfig {
            kad_sweep_interval: Duration::from_millis(10),
            ..crate::fixture::search_config()
        },
        rmule_testkit::memory_store(),
    )
    .settings(rmule_testkit::in_download_dir(
        rmule_core::CoreSettings::default(),
        dir.path(),
    ))
    .peer_transfer(ScriptedPeerTransfer {
        expected_peer: kad_source.as_peer_endpoint().unwrap(),
        outcome: PeerDownloadOutcome {
            peer_hashes: Vec::new(),
            parts: vec![DownloadedPart {
                part_index: 0,
                offset: 0,
                bytes: bytes.clone(),
            }],
        },
    })
    .kad(channel)
    .build();
    assert!(
        core.diagnostics_snapshot().servers.is_empty(),
        "no server listed"
    );
    core.send(CoreCommand::EnableKad(kad_enable_config()))
        .await
        .unwrap();

    let search_id = rmule_core::SearchId::mint();
    core.send(CoreCommand::Search(
        rmule_core::SearchCommand::StartSearch {
            search_id,
            query: crate::fixture::search_query("kad only").into(),
        },
    ))
    .await
    .unwrap();
    let found = crate::fixture::next_expected(&mut core, "the Kad row", |event| {
        matches!(
            event,
            CoreEvent::Search(rmule_core::SearchEvent::SearchResultsReceived { results, .. })
                if !results.is_empty()
        )
    })
    .await;
    let CoreEvent::Search(rmule_core::SearchEvent::SearchResultsReceived { results, .. }) = found
    else {
        unreachable!()
    };

    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: results[0].to_file_link(),
        source_hint: None,
        name: rmule_testkit::file_name("kad-only.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
        kad_aich_root: None,
    }))
    .await
    .unwrap();

    let mut events = Vec::new();
    timeout(HANG_GUARD, async {
        loop {
            let event = core.next_event().await.expect("core alive");
            let done = matches!(
                event,
                CoreEvent::Download(DownloadEvent::DownloadCompleted { .. })
            );
            events.push(event);
            if done {
                return;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the download never completed: {events:?}"));
    assert!(
        events.iter().any(|event| matches!(
            event,
            CoreEvent::Download(DownloadEvent::PartAssigned { .. })
        )),
        "a part was fetched from the Kad peer: {events:?}"
    );
    assert!(
        !events.iter().any(|event| matches!(
            event,
            CoreEvent::ServerConnection(_)
                | CoreEvent::Download(DownloadEvent::WaitingForConnection { .. })
        )),
        "nothing logged in, and Kad was a connection: {events:?}"
    );
}
