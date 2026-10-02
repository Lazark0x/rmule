//! A second link for a file a download already runs for (ADR-0089):
//! its sources join the running download's candidate pool, as aMule
//! (`DownloadQueue.cpp:1461-1500`) and eMule (`DownloadQueue.cpp:271-295`) add
//! them — no second row, no refusal — and a second link that names no source
//! is still refused as the duplicate it is.

use rmule_core::{
    Core, CoreCommand, CoreCommandRejectReason, CoreConfig, CoreEvent, DownloadCommand,
    DownloadEvent, DownloadFailure, PeerTransferService, PeerWorker, PeerWorkerEvent,
    SourceLookupOutcome, SourceLookupService,
};
use rmule_peer::PeerHandshakeContext;
use rmule_primitives::{
    ClientId, Ed2kFileLink, Ed2kLink, ExchangedSource, PeerEndpoint, PeerSource, SourceLookupTarget,
};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::fixture::{identity, stub_server};

const HASH: &str = "31D6CFE0D16AE931B73C59D7E0C089C0";

fn file_link(tail: &str) -> Ed2kFileLink {
    match Ed2kLink::read(&format!("ed2k://|file|second.bin|11|{HASH}|/{tail}"))
        .expect("a well-formed link")
        .link
    {
        Ed2kLink::File(file) => file,
        other => panic!("expected a file link, got {other:?}"),
    }
}

/// `10.0.0.9:4663` as the server names it (client ids carry the IP
/// little-endian).
fn server_source() -> PeerSource {
    PeerSource::new(ClientId::from_u32(u32::from_le_bytes([10, 0, 0, 9])), 4663)
}

#[derive(Clone)]
struct OneSourceLookup;

impl SourceLookupService for OneSourceLookup {
    async fn lookup_sources(
        &mut self,
        _target: SourceLookupTarget,
    ) -> Result<SourceLookupOutcome, DownloadFailure> {
        Ok(SourceLookupOutcome {
            client_id: ClientId::from_u32(0x0100_007F),
            sources: vec![ExchangedSource::plain(server_source())],
        })
    }
}

/// Reports every dial, and holds each worker connected without ever
/// delivering, so the run stays running.
struct DialRecorder {
    dials: mpsc::UnboundedSender<PeerEndpoint>,
}

impl PeerTransferService for DialRecorder {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        _ctx: PeerHandshakeContext,
        _file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        let _ = self.dials.send(peer);
        let (command_tx, mut command_rx) = mpsc::channel(8);
        let (event_tx, event_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            let _ = event_tx.send(PeerWorkerEvent::Connected).await;
            while command_rx.recv().await.is_some() {}
        });
        Ok(PeerWorker::new(peer, command_tx, event_rx))
    }
}

async fn next_event(core: &mut Core) -> CoreEvent {
    timeout(Duration::from_secs(5), core.next_event())
        .await
        .expect("core emitted next event")
        .expect("core event stream stayed open")
}

async fn next_dial(dials: &mut mpsc::UnboundedReceiver<PeerEndpoint>) -> PeerEndpoint {
    timeout(Duration::from_secs(5), dials.recv())
        .await
        .expect("a dial within 5 s")
        .expect("the recorder stayed open")
}

fn start(file: Ed2kFileLink, out: &std::path::Path) -> CoreCommand {
    CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: Some(stub_server("127.0.0.1")),
        credentials: identity().into(),
        output_path: out.join("second.bin"),
    })
}

#[tokio::test]
async fn a_second_link_adds_its_sources_to_the_running_download() {
    let (dials_tx, mut dials) = mpsc::unbounded_channel();
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .source_lookup(OneSourceLookup)
        .peer_transfer(DialRecorder { dials: dials_tx })
        .build();
    let out = tempfile::tempdir().unwrap();

    core.send(start(file_link(""), out.path())).await.unwrap();
    let download_id = loop {
        if let CoreEvent::Download(DownloadEvent::DownloadQueued { download_id, .. }) =
            next_event(&mut core).await
        {
            break download_id;
        }
    };
    assert_eq!(
        next_dial(&mut dials).await,
        server_source().as_peer_endpoint().unwrap(),
        "the run starts on the server's source"
    );

    core.send(start(
        file_link("|sources,198.51.100.23:4665,198.51.100.23:4665|/"),
        out.path(),
    ))
    .await
    .unwrap();
    loop {
        match next_event(&mut core).await {
            CoreEvent::Download(DownloadEvent::LinkSourcesAdded {
                download_id: id,
                named,
                admitted,
                new,
            }) => {
                assert_eq!(
                    (id, named, admitted, new),
                    (download_id, 2, 2, 1),
                    "a source the link names twice is one new source"
                );
                break;
            }
            CoreEvent::Download(DownloadEvent::DownloadQueued { .. }) => {
                panic!("a second link made a second download")
            }
            CoreEvent::CommandRejected { reason } => {
                panic!("a second link with a source was refused: {reason:?}")
            }
            _ => {}
        }
    }
    assert_eq!(
        next_dial(&mut dials).await.to_string(),
        "198.51.100.23:4665",
        "the link's source joined the pool and took the free slot"
    );

    // The same link again: its source is the one the run already works, so
    // nothing new joins and nothing is dialed twice.
    core.send(start(
        file_link("|sources,198.51.100.23:4665|/"),
        out.path(),
    ))
    .await
    .unwrap();
    loop {
        if let CoreEvent::Download(DownloadEvent::LinkSourcesAdded {
            named,
            admitted,
            new,
            ..
        }) = next_event(&mut core).await
        {
            assert_eq!((named, admitted, new), (1, 1, 0));
            break;
        }
    }
    assert!(
        timeout(Duration::from_millis(200), dials.recv())
            .await
            .is_err(),
        "a source the run already knows is not dialed again"
    );

    core.send(start(file_link(""), out.path())).await.unwrap();
    loop {
        match next_event(&mut core).await {
            CoreEvent::CommandRejected { reason } => {
                assert_eq!(reason, CoreCommandRejectReason::DuplicateDownload);
                break;
            }
            CoreEvent::Download(DownloadEvent::LinkSourcesAdded { .. }) => {
                panic!("a link with no source added some")
            }
            _ => {}
        }
    }
}
