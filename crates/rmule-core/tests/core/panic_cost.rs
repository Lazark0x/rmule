//! What a panic costs in a build that unwinds, and what quit writes before
//! anything slow can cut it short (ADR-0118).

use std::time::Duration;

use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand, DownloadEvent, DownloadFailure,
    NameTaken, PeerDownloadOutcome, SourceLookupOutcome, SourceLookupService,
};
use rmule_primitives::{SafeFileName, ServerEndpoint, SourceLookupTarget};
use rmule_testkit::{StaticPeerTransfer, file_link};
use tokio::time::timeout;

/// Far past a task's turn, far short of the hang guard.
const BOUND: Duration = Duration::from_secs(20);

#[derive(Clone)]
struct PanickingLookup;

impl SourceLookupService for PanickingLookup {
    async fn lookup_sources(
        &mut self,
        _target: SourceLookupTarget,
    ) -> Result<SourceLookupOutcome, DownloadFailure> {
        panic!("a defect in a download run");
    }
}

#[derive(Clone)]
struct SilentLookup;

impl SourceLookupService for SilentLookup {
    async fn lookup_sources(
        &mut self,
        _target: SourceLookupTarget,
    ) -> Result<SourceLookupOutcome, DownloadFailure> {
        std::future::pending().await
    }
}

async fn start_download(core: &Core) {
    let file = file_link("panic.bin", &[7; 64]);
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        name: SafeFileName::of_link(&file),
        file,
        source_hint: Some(ServerEndpoint::new("203.0.113.9", 4661).unwrap()),
        if_taken: NameTaken::Refuse,
        kad_aich_root: None,
    }))
    .await
    .expect("the core takes the command");
}

#[tokio::test]
async fn a_panicked_run_fails_its_row() {
    let out_dir = tempfile::tempdir().expect("tempdir");
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            out_dir.path(),
        ))
        .source_lookup(PanickingLookup)
        .peer_transfer(StaticPeerTransfer {
            expected_plan_count: 0,
            outcome: PeerDownloadOutcome {
                peer_hashes: Vec::new(),
                parts: Vec::new(),
            },
        })
        .build();
    start_download(&core).await;
    let failed = timeout(BOUND, async {
        loop {
            match core.next_event().await {
                Some(CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. })) => {
                    return Some(reason);
                }
                Some(_) => {}
                None => return None,
            }
        }
    })
    .await
    .expect("the run's death reaches its row");
    assert_eq!(failed, Some(DownloadFailure::TaskPanicked));
}

#[tokio::test(flavor = "multi_thread")]
async fn quit_writes_the_credit_before_its_first_step_can_be_slow() {
    let out_dir = tempfile::tempdir().expect("tempdir");
    let credit_dir = tempfile::tempdir().expect("tempdir");
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            out_dir.path(),
        ))
        .source_lookup(SilentLookup)
        .peer_transfer(StaticPeerTransfer {
            expected_plan_count: 0,
            outcome: PeerDownloadOutcome {
                peer_hashes: Vec::new(),
                parts: Vec::new(),
            },
        })
        .persist_credit_in(credit_dir.path().to_path_buf())
        .build();
    start_download(&core).await;
    timeout(BOUND, async {
        while !matches!(
            core.next_event().await,
            Some(CoreEvent::Download(DownloadEvent::DownloadQueued { .. }))
        ) {}
    })
    .await
    .expect("the download starts");

    let mut quit = core.quit();
    let first = timeout(BOUND, async {
        loop {
            match quit.recv().await {
                Some(CoreEvent::Quitting { step }) => return Some(step),
                Some(_) => {}
                None => return None,
            }
        }
    })
    .await
    .expect("quit announces a step");
    assert_ne!(first, Some(rmule_core::QuitStep::CreditCheckpoint));
    assert!(
        credit_dir.path().join("clients.met").exists(),
        "the snapshot stands before the first step runs"
    );
}
