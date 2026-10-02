//! What the default `Core` does when its runtime adapters meet a server that
//! isn't there: with Kad off the refused connect leaves the download with no
//! connection, which it says and waits out (ADR-0093, "Waiting for a
//! connection") rather than failing or hanging silently.

use rmule_core::{Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand, DownloadEvent};
use rmule_primitives::ServerEndpoint;
use tokio::time::{Duration, timeout};

use crate::fixture::{dead_port, identity};
use rmule_testkit::file_link_without_part_hash_set;

#[tokio::test]
async fn default_core_waits_for_a_connection_when_its_server_is_not_there() {
    let port = dead_port().await;
    let output_dir = tempfile::tempdir().expect("temp dir");

    let mut core = Core::new(CoreConfig::default(), rmule_testkit::memory_store());
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: file_link_without_part_hash_set("example.bin", b"hello world"),
        source_hint: Some(ServerEndpoint::new("127.0.0.1", port).unwrap()),
        credentials: identity().into(),
        output_path: output_dir.path().join("example.bin"),
    }))
    .await
    .unwrap();

    loop {
        let event = timeout(Duration::from_secs(3), core.next_event())
            .await
            .expect("core emitted next event")
            .expect("core event stream stayed open");
        match event {
            CoreEvent::Download(DownloadEvent::WaitingForConnection { .. }) => break,
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("a missing connection is not a failure: {reason:?}")
            }
            _ => {}
        }
    }
}
