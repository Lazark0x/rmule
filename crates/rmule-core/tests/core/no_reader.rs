//! A front end that stops reading costs the node nothing (ADR-0069, "Core
//! never waits on the front end").
use crate::fixture::stub_link;
use rmule_core::{Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand, DownloadEvent};
use rmule_core::{NameTaken, open_durable_store};
use rmule_testkit::HANG_GUARD;
use std::sync::Arc;
use tokio::time::timeout;

const DOWNLOADS: u8 = 60;
const DUMPS: usize = 200;

/// Nothing reads the event stream, while the commands go on well past every
/// queue between a key and the actor: the runs start, the actor takes every
/// command, and when a reader comes back every Edge is there, in order.
#[tokio::test]
async fn a_core_nobody_reads_keeps_taking_commands_and_loses_no_edge() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_durable_store(dir.path()).unwrap();
    let mut core = Core::builder(CoreConfig::default(), Arc::clone(&store))
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            dir.path(),
        ))
        .build();

    timeout(HANG_GUARD, async {
        for seed in 0..DOWNLOADS {
            let name = format!("file-{seed}.bin");
            let file = stub_link(&name, 3, seed);
            core.send(CoreCommand::Download(DownloadCommand::StartDownload {
                file,
                source_hint: None,
                name: rmule_testkit::file_name(&name),
                if_taken: NameTaken::Refuse,
                kad_aich_root: None,
            }))
            .await
            .unwrap();
        }
        for _ in 0..DUMPS {
            core.send(CoreCommand::DumpFileHistory).await.unwrap();
        }
    })
    .await
    .expect("the actor takes commands with nobody reading its events");

    timeout(HANG_GUARD, async {
        let (mut queued, mut dumps) = (0, 0);
        while dumps < DUMPS {
            match core.next_event().await.expect("the core runs") {
                CoreEvent::Download(DownloadEvent::DownloadQueued { .. }) => queued += 1,
                CoreEvent::FileHistory { .. } => dumps += 1,
                _ => {}
            }
        }
        assert_eq!(queued, usize::from(DOWNLOADS));
    })
    .await
    .expect("every Edge waited for the reader");
}
