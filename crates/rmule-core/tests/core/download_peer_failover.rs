//! A download carried by the peers that can deliver, over the loopback
//! counterparties: a source whose eD2k hello never arrives stays off the
//! runner's critical path (ADR-0030), a peer that queues us forever is raced by
//! one that grants, and a peer that closes mid-part leaves a prefix the next
//! peer resumes from rather than restarting at block 0 (ADR-0029).

use crate::fixture::identity_with_port;
use std::time::Duration;

use crate::fixture::identity;
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
    // alongside the healthy one (peer_concurrency defaults to 2).
    server
        .set_sources(vec![silent.source(), good.source()])
        .await;
    let silent_task = silent.spawn_silent();
    let good_task = good.spawn(PeerScript::serving(file_hash, bytes));

    let out = tempfile::tempdir().unwrap();
    let mut core = Core::new(CoreConfig::default(), rmule_testkit::memory_store());
    rmule_testkit::connect_to(&core, &server.endpoint(), identity_with_port(0).into()).await;
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: Some(server.endpoint()),
        credentials: identity().into(),
        output_path: out.path().join("silent-source.bin"),
    }))
    .await
    .unwrap();

    loop {
        let event = timeout(Duration::from_secs(5), core.next_event())
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
async fn core_single_part_race_completes_when_primary_peer_queues_forever() {
    // A single-part file with one slow peer (assigned the part
    // first) that queues us forever and one peer that grants instantly.
    // The granting peer must be allowed to race the same part rather than
    // sit idle, so the download completes instead of stalling on the slow
    // primary.
    let bytes = b"raced single part loopback download".to_vec();
    let file = file_link("loopback.bin", &bytes);
    let file_hash = file.file_hash;

    let server = FakeEd2kServer::start_scripted().await;
    let slow = FakePeer::bind().await;
    let fast = FakePeer::bind().await;
    let slow_port = slow.addr().port();
    let fast_port = fast.addr().port();
    // Slow peer first: it is assigned the only part, the fast peer races it.
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
    let mut core = Core::new(config, rmule_testkit::memory_store());
    rmule_testkit::connect_to(&core, &server.endpoint(), identity_with_port(0).into()).await;
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: Some(server.endpoint()),
        credentials: identity().into(),
        output_path: out.path().join("race.bin"),
    }))
    .await
    .unwrap();

    let mut assigned_to = std::collections::HashSet::new();
    loop {
        let event = timeout(Duration::from_secs(5), core.next_event())
            .await
            .expect("core emitted event")
            .expect("core event stream stayed open");
        match event {
            CoreEvent::Download(DownloadEvent::PartAssigned { peer, .. }) => {
                assigned_to.insert(peer.port());
            }
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. }) => break,
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("download failed: {reason:?}")
            }
            _ => {}
        }
    }

    assert!(
        assigned_to.contains(&slow_port) && assigned_to.contains(&fast_port),
        "both peers must race the single part; assigned to ports {assigned_to:?}"
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
    let mut core = Core::new(config, rmule_testkit::memory_store());
    rmule_testkit::connect_to(&core, &server.endpoint(), identity_with_port(0).into()).await;
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: Some(server.endpoint()),
        credentials: identity().into(),
        output_path: out.path().join("drop-resume.bin"),
    }))
    .await
    .unwrap();

    loop {
        let event = timeout(Duration::from_secs(10), core.next_event())
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
