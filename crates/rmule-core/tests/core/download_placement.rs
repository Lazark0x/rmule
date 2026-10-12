//! Where a download lands: core places every start in the download directory
//! its Core Settings name, judged by the share guards at the start (ADR-0069,
//! ADR-0101). A command names the file only, so no front end can send a
//! download where the guards would refuse to share it.

use rmule_testkit::HANG_GUARD;
use std::path::Path;
use std::time::Duration;

use rmule_core::{
    Core, CoreCommand, CoreCommandRejectReason, CoreConfig, CoreEvent, CoreSettings,
    DirectoryRefusal, DownloadCommand, DownloadEvent, NameTaken, ShareGuards,
};
use rmule_primitives::{Ed2kFileLink, Ed2kLink, SafeFileName};
use rmule_testkit::{FakePeer, PeerScript, file_link};
use tokio::time::timeout;

fn core_in(download_dir: Option<&Path>, guards: ShareGuards) -> Core {
    Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(CoreSettings {
            download_dir: download_dir.map(Path::to_path_buf),
            ..CoreSettings::default()
        })
        .share_guards(guards)
        .build()
}

fn start(file: Ed2kFileLink, if_taken: NameTaken) -> CoreCommand {
    CoreCommand::Download(DownloadCommand::StartDownload {
        name: SafeFileName::of_link(&file),
        file,
        source_hint: None,
        if_taken,
    })
}

/// A start's answer: its `DownloadQueued`, or the refusal in its place.
async fn verdict(core: &mut Core) -> CoreEvent {
    loop {
        let event = timeout(HANG_GUARD, core.next_event())
            .await
            .expect("core answered the start")
            .expect("core event stream stayed open");
        if matches!(
            event,
            CoreEvent::Download(DownloadEvent::DownloadQueued { .. })
                | CoreEvent::CommandRejected { .. }
        ) {
            return event;
        }
    }
}

#[tokio::test]
async fn a_start_with_no_download_directory_is_refused() {
    let mut core = core_in(None, ShareGuards::default());

    core.send(start(file_link("nowhere.bin", b"abc"), NameTaken::Refuse))
        .await
        .unwrap();

    let answer = verdict(&mut core).await;
    assert!(
        matches!(
            answer,
            CoreEvent::CommandRejected {
                reason: CoreCommandRejectReason::NoDownloadDir
            }
        ),
        "got {answer:?}",
    );
    core.shutdown().await;
}

/// A download directory the guards refuse — the operator's home here — takes
/// no download, so nothing completes where it would be shared.
#[tokio::test]
async fn a_start_into_a_refused_download_directory_is_refused() {
    let home = tempfile::tempdir().unwrap();
    let guards = ShareGuards {
        home: Some(home.path().to_path_buf()),
        data_dir: None,
    };
    let mut core = core_in(Some(home.path()), guards);

    core.send(start(file_link("home.bin", b"abc"), NameTaken::Refuse))
        .await
        .unwrap();

    let answer = verdict(&mut core).await;
    assert!(
        matches!(
            answer,
            CoreEvent::CommandRejected {
                reason: CoreCommandRejectReason::DownloadDirRefused(
                    DirectoryRefusal::HomeDirectory
                )
            }
        ),
        "got {answer:?}",
    );
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
    core.shutdown().await;
}

/// ADR-0100, re-adding a file the operator has: the copy on disk is never
/// written over. A fresh add of the name is refused; the confirmed re-add
/// lands under the first free numbered name beside it.
#[tokio::test]
async fn a_re_add_lands_beside_the_copy_on_disk() {
    let bytes = b"the same name, fetched again".to_vec();
    let peer = FakePeer::bind().await;
    let at = peer.addr();
    let file = file_link("have.bin", &bytes);
    let peer_task = peer.spawn(PeerScript::serving(file.file_hash, bytes.clone()));
    let canonical = Ed2kLink::File(file).to_string();
    let text = format!("{}sources,{at}|/", canonical.strip_suffix('/').unwrap());
    let Ok(Ed2kLink::File(linked)) = Ed2kLink::parse(&text) else {
        panic!("the link with its source stands: {text}");
    };
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("have.bin"), b"kept").unwrap();
    let mut core = core_in(Some(dir.path()), ShareGuards::default());

    core.send(start(linked.clone(), NameTaken::Refuse))
        .await
        .unwrap();
    let answer = verdict(&mut core).await;
    assert!(
        matches!(
            answer,
            CoreEvent::CommandRejected {
                reason: CoreCommandRejectReason::DownloadPathConflict
            }
        ),
        "got {answer:?}",
    );
    core.send(start(linked, NameTaken::Number)).await.unwrap();
    let final_path = loop {
        let event = timeout(HANG_GUARD, core.next_event())
            .await
            .expect("core emitted event")
            .expect("core event stream stayed open");
        match event {
            CoreEvent::Download(DownloadEvent::DownloadCompleted { final_path, .. }) => {
                break final_path;
            }
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("download failed: {reason:?}")
            }
            CoreEvent::CommandRejected { reason } => panic!("re-add refused: {reason:?}"),
            _ => {}
        }
    };

    assert_eq!(std::fs::read(dir.path().join("have.bin")).unwrap(), b"kept");
    assert_eq!(
        std::fs::read(dir.path().join("have (1).bin")).unwrap(),
        bytes
    );
    // The completion names the numbered file it made, not the name asked for.
    assert_eq!(
        final_path.file_name().and_then(|name| name.to_str()),
        Some("have (1).bin")
    );
    assert_eq!(std::fs::read(&final_path).unwrap(), bytes);
    core.shutdown().await;
    let _ = timeout(Duration::from_secs(5), peer_task).await;
}
