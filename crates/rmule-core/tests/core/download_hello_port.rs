//! The TCP port a running download's hello presents when the Core Settings
//! name `0` (the OS's choice): the port the listener holds bound as each
//! hello is sent, so a listener restarted on another port is named from then
//! on, never the one bound when the download started.

use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand, DownloadFailure,
    PeerTransferService, PeerWorker, PeerWorkerEvent, ServeCommand, ServeEvent,
    SourceLookupOutcome,
};
use rmule_peer::PeerHandshakeContext;
use rmule_primitives::{ClientId, Ed2kFileLink, Ed2kLink, PeerEndpoint, PeerSource};
use rmule_testkit::HANG_GUARD;
use rmule_testkit::{StaticSourceLookup, plain_sources};
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::fixture::{free_port, next_expected, serving_started, settings_on, stub_server};

const HASH: &str = "31D6CFE0D16AE931B73C59D7E0C089C0";

fn file_link(tail: &str) -> Ed2kFileLink {
    match Ed2kLink::read(&format!("ed2k://|file|port.bin|11|{HASH}|/{tail}"))
        .expect("a well-formed link")
        .link
    {
        Ed2kLink::File(file) => file,
        other => panic!("expected a file link, got {other:?}"),
    }
}

/// Reports every dial with the TCP port its hello presents, and holds each
/// worker connected without ever delivering, so the run stays running.
struct HelloRecorder {
    hellos: mpsc::UnboundedSender<(PeerEndpoint, u16)>,
}

impl PeerTransferService for HelloRecorder {
    async fn start_peer_worker(
        &mut self,
        peer: PeerEndpoint,
        ctx: PeerHandshakeContext,
        file: Ed2kFileLink,
    ) -> Result<PeerWorker, DownloadFailure> {
        let advertised = rmule_testkit::every_part(file.size);
        let _ = self.hellos.send((peer, ctx.identity.tcp_port()));
        let (command_tx, mut command_rx) = mpsc::channel(8);
        let (event_tx, event_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            let _ = event_tx.send(PeerWorkerEvent::Connected).await;
            let _ = event_tx.send(advertised).await;
            while command_rx.recv().await.is_some() {}
        });
        Ok(PeerWorker::new(peer, command_tx, event_rx))
    }
}

async fn next_hello(hellos: &mut mpsc::UnboundedReceiver<(PeerEndpoint, u16)>) -> (String, u16) {
    let (peer, port) = timeout(HANG_GUARD, hellos.recv())
        .await
        .expect("a dial")
        .expect("the recorder stayed open");
    (peer.to_string(), port)
}

fn start(file: Ed2kFileLink) -> CoreCommand {
    CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: Some(stub_server("127.0.0.1")),
        name: rmule_testkit::file_name("port.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
        kad_aich_root: None,
    })
}

async fn start_serving(core: &mut Core, port: u16) -> u16 {
    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: format!("127.0.0.1:{port}").parse().unwrap(),
    }))
    .await
    .unwrap();
    serving_started(core).await.port()
}

#[tokio::test]
async fn a_running_download_names_the_port_its_restarted_listener_bound() {
    let out = tempfile::tempdir().unwrap();
    let (hellos_tx, mut hellos) = mpsc::unbounded_channel();
    let lookup = StaticSourceLookup {
        outcome: SourceLookupOutcome {
            client_id: ClientId::from_u32(0x0100_007F),
            sources: plain_sources(vec![PeerSource::new(ClientId::from_u32(0x0100_007F), 4663)]),
        },
    };
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_testkit::in_download_dir(settings_on(0), out.path()))
        .source_lookup(lookup)
        .peer_transfer(HelloRecorder { hellos: hellos_tx })
        .build();

    let first = start_serving(&mut core, 0).await;
    core.send(start(file_link(""))).await.unwrap();
    assert_eq!(
        next_hello(&mut hellos).await,
        ("127.0.0.1:4663".to_owned(), first)
    );

    core.send(CoreCommand::Serve(ServeCommand::StopServing))
        .await
        .unwrap();
    next_expected(&mut core, "the listener stopped", |event| {
        matches!(event, CoreEvent::Serve(ServeEvent::ServingStopped { .. }))
    })
    .await;
    let second = start_serving(&mut core, free_port().await).await;
    assert_ne!(first, second);

    core.send(start(file_link("|sources,198.51.100.23:4665|/")))
        .await
        .unwrap();
    assert_eq!(
        next_hello(&mut hellos).await,
        ("198.51.100.23:4665".to_owned(), second),
        "the next hello names the port the listener holds now"
    );
    core.shutdown().await;
}
