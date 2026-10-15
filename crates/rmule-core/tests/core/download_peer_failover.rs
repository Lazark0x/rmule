//! A download carried by the peers that can deliver, over the loopback
//! counterparties: a source whose eD2k hello never arrives stays off the
//! runner's critical path (ADR-0030), a peer that queues us forever holds no
//! part while one that grants carries it (ADR-0026), and a peer that closes
//! mid-part leaves a prefix the next peer resumes from rather than restarting
//! at block 0 (ADR-0029).

use rmule_testkit::HANG_GUARD;
use std::time::Duration;

use rmule_core::{Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand, DownloadEvent};
use rmule_testkit::{FakeEd2kServer, FakePeer, PeerScript, ServePolicy, SlotPolicy, file_link};
use tokio::time::timeout;

#[tokio::test]
async fn core_completes_when_one_source_never_finishes_handshake() {
    // Proven end to end through the real transport:
    // one High-ID source accepts the TCP connection but never sends
    // HelloAnswer — a dead/firewalled peer whose eD2k hello hangs. With
    // event-driven identification (ADR-0030) that worker's stalled handshake
    // runs off the runner's critical path, so a second, healthy source still
    // carries the download to completion.
    let bytes = b"silent source loopback download".to_vec();
    let file = file_link("loopback.bin", &bytes);
    let file_hash = file.file_hash;

    let server = FakeEd2kServer::start_scripted().await;
    let silent = FakePeer::bind().await;
    let good = FakePeer::bind().await;
    // Silent source listed first so it joins the initial spawn batch
    // alongside the healthy one.
    server
        .set_sources(vec![silent.source(), good.source()])
        .await;
    let silent_task = silent.spawn_silent();
    let good_task = good.spawn(PeerScript::serving(file_hash, bytes));

    let out = tempfile::tempdir().unwrap();
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            out.path(),
        ))
        .build();
    rmule_testkit::connect_to(&core, &server.endpoint()).await;
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: Some(server.endpoint()),
        name: rmule_testkit::file_name("silent-source.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
    }))
    .await
    .unwrap();

    loop {
        let event = timeout(HANG_GUARD, core.next_event())
            .await
            .expect("core emitted event")
            .expect("core event stream stayed open");
        match event {
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. }) => break,
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("download failed: {reason:?}")
            }
            _ => {}
        }
    }

    silent_task.abort();
    // Serving keeps the dialed link open for uploads (ADR-0031);
    // the peer script ends when the core does.
    core.shutdown().await;
    let _ = good_task.await;
}

#[tokio::test]
async fn core_single_part_completes_through_the_grant_while_another_peer_queues_forever() {
    // A single-part file with one slow peer that queues us forever and one
    // that grants at once. Both ask their slot at their probe answers, and the
    // part is handed at a grant (ADR-0026, "The slot ask"): the granting peer
    // carries it, and the slow one, queued, holds no part for the download to
    // stall on.
    let bytes = b"raced single part loopback download".to_vec();
    let file = file_link("loopback.bin", &bytes);
    let file_hash = file.file_hash;

    let server = FakeEd2kServer::start_scripted().await;
    let slow = FakePeer::bind().await;
    let fast = FakePeer::bind().await;
    let slow_port = slow.addr().port();
    let fast_port = fast.addr().port();
    // Slow peer first: it asks its slot first, and is never granted.
    server.set_sources(vec![slow.source(), fast.source()]).await;
    let slow_task = slow.spawn(PeerScript {
        slot: SlotPolicy::QueueForever {
            start_rank: 9,
            interval: Duration::from_millis(50),
        },
        serve: ServePolicy::Nothing,
        ..PeerScript::serving(file_hash, bytes.clone())
    });
    let fast_task = fast.spawn(PeerScript::serving(file_hash, bytes));

    let config = CoreConfig {
        peer_concurrency_per_download: 2,
        ..CoreConfig::default()
    };
    let out = tempfile::tempdir().unwrap();
    let mut core = Core::builder(config, rmule_testkit::memory_store())
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            out.path(),
        ))
        .build();
    rmule_testkit::connect_to(&core, &server.endpoint()).await;
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: Some(server.endpoint()),
        name: rmule_testkit::file_name("race.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
    }))
    .await
    .unwrap();

    let mut assigned_to = std::collections::HashSet::new();
    let mut queued_at = std::collections::HashSet::new();
    loop {
        let event = timeout(HANG_GUARD, core.next_event())
            .await
            .expect("core emitted event")
            .expect("core event stream stayed open");
        match event {
            CoreEvent::Download(DownloadEvent::PartAssigned { peer, .. }) => {
                assigned_to.insert(peer.port());
            }
            CoreEvent::Download(DownloadEvent::PeerQueued { peer, .. }) => {
                queued_at.insert(peer.port());
            }
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. }) => break,
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("download failed: {reason:?}")
            }
            _ => {}
        }
    }

    assert!(
        queued_at.contains(&slow_port),
        "the slow peer's slot ask went out and it queued us: {queued_at:?}"
    );
    assert_eq!(
        assigned_to,
        std::collections::HashSet::from([fast_port]),
        "the part goes to the grant; a peer queued forever holds none"
    );

    slow_task.abort();
    // Serving keeps the dialed link open for uploads (ADR-0031);
    // the peer script ends when the core does.
    core.shutdown().await;
    let _ = fast_task.await;
}

#[tokio::test]
async fn core_finishes_a_part_from_a_second_peer_after_the_first_drops_mid_part() {
    // ADR-0029 end to end through the real transport: peer 1 serves the
    // first EMBLOCKSIZE block of a multi-block single part then closes mid-part.
    // Core preserves the shared prefix and hands peer 2 a resume offset of
    // EMBLOCKSIZE, so peer 2 finishes the part from there instead of restarting at
    // block 0. peer_concurrency = 1 sequences the drop and the backfill.
    let block = rmule_peer::EMBLOCKSIZE as usize;
    let mut bytes = vec![0u8; block * 2 + 5000];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let file = file_link("loopback.bin", &bytes);
    let file_hash = file.file_hash;

    let server = FakeEd2kServer::start_scripted().await;
    let dropping = FakePeer::bind().await;
    let finishing = FakePeer::bind().await;
    // Dropping peer first so peer_concurrency = 1 spawns it first; the
    // finishing peer is reached only via backfill after the drop.
    server
        .set_sources(vec![dropping.source(), finishing.source()])
        .await;
    let drop_task = dropping.spawn(PeerScript {
        serve: ServePolicy::FirstBlockThenClose,
        ..PeerScript::serving(file_hash, bytes.clone())
    });
    let finish_task = finishing.spawn(PeerScript::serving(file_hash, bytes.clone()));

    let config = CoreConfig {
        peer_concurrency_per_download: 1,
        ..CoreConfig::default()
    };
    let out = tempfile::tempdir().unwrap();
    let mut core = Core::builder(config, rmule_testkit::memory_store())
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            out.path(),
        ))
        .build();
    rmule_testkit::connect_to(&core, &server.endpoint()).await;
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: Some(server.endpoint()),
        name: rmule_testkit::file_name("drop-resume.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
    }))
    .await
    .unwrap();

    loop {
        let event = timeout(HANG_GUARD, core.next_event())
            .await
            .expect("core emitted event")
            .expect("core event stream stayed open");
        match event {
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. }) => break,
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("download failed: {reason:?}")
            }
            _ => {}
        }
    }

    drop_task.abort();
    // Serving keeps the dialed link open for uploads (ADR-0031);
    // the peer script ends when the core does.
    core.shutdown().await;
    let stats = finish_task.await.unwrap();
    assert_eq!(
        stats.first_request_start,
        Some(rmule_peer::EMBLOCKSIZE),
        "the second peer must resume at the dropped prefix end (EMBLOCKSIZE), not restart at 0"
    );
}
