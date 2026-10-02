//! Downloads that run end to end over the testkit counterparties (Correctness
//! Tier, ADR-0040): `FakeEd2kServer` in scripted mode stands in for the
//! connected server and `FakePeer` serves the parts, with one happy path run
//! against a real serving core (`ServingCore`) per the both-fakes policy. The
//! shapes proven here are the ordinary ones — a single part, a multi-block
//! part, two parts across two peers, and the server-UDP rescue of a download
//! the connected server had no source for.

use crate::fixture::identity_with_port;
use std::time::Duration;

use crate::fixture::identity;
use rmule_core::diagnostics::PartState;
use rmule_core::{Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand, DownloadEvent};
use rmule_primitives::{Ed2kLink, ServerEndpoint};
use rmule_testkit::{
    FakeEd2kServer, FakePeer, FakeServerUdp, HashSetPolicy, PeerScript, ServingCore, file_link,
};
use tokio::time::timeout;

#[tokio::test]
async fn core_download_completes_against_loopback_server_and_peer() {
    let bytes = b"hello loopback download".to_vec();
    let file = file_link("loopback.bin", &bytes);
    let file_hash = file.file_hash;

    let server = FakeEd2kServer::start_scripted().await;
    let peer = FakePeer::bind().await;
    server.set_sources(vec![peer.source()]).await;
    let peer_task = peer.spawn(PeerScript::serving(file_hash, bytes));

    let out = tempfile::tempdir().unwrap();
    let mut core = Core::new(CoreConfig::default(), rmule_testkit::memory_store());
    rmule_testkit::connect_to(&core, &server.endpoint(), identity_with_port(0).into()).await;
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: Some(server.endpoint()),
        credentials: identity().into(),
        output_path: out.path().join("download-loopback.bin"),
    }))
    .await
    .unwrap();

    let mut saw_login = false;
    let mut saw_sources = false;
    let mut saw_peer = false;
    let mut saw_hashset = false;
    let mut saw_part = false;
    loop {
        let event = timeout(Duration::from_secs(5), core.next_event())
            .await
            .expect("core emitted event")
            .expect("core event stream stayed open");
        match event {
            CoreEvent::Download(DownloadEvent::ServerLoginAccepted { .. }) => saw_login = true,
            CoreEvent::Download(DownloadEvent::SourcesFound {
                total: 1,
                usable_high_id: 1,
                ..
            }) => saw_sources = true,
            CoreEvent::Download(DownloadEvent::PeerSelected { .. }) => saw_peer = true,
            CoreEvent::Download(DownloadEvent::HashSetReceived { .. }) => saw_hashset = true,
            CoreEvent::Download(DownloadEvent::PartVerified { part_index: 0, .. }) => {
                saw_part = true
            }
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. }) => break,
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("download failed: {reason:?}")
            }
            _ => {}
        }
    }

    assert!(saw_login, "ServerLoginAccepted emitted");
    assert!(saw_sources, "SourcesFound emitted");
    assert!(saw_peer, "PeerSelected emitted");
    assert!(saw_hashset, "HashSetReceived emitted");
    assert!(saw_part, "PartVerified emitted");

    // The completion counterpart to the cancel proof (ADR-0056): a normal
    // completion releases each slot silently, so no `OP_CANCELTRANSFER` (0x56)
    // is ever put on the wire — the 0x56 belongs to the cancel/abandon path
    // alone.
    // Serving keeps the dialed link open for uploads (ADR-0031);
    // the peer script ends when the core does.
    core.shutdown().await;
    let stats = timeout(Duration::from_secs(5), peer_task)
        .await
        .expect("the peer script finished within 5s")
        .expect("peer task");
    assert_eq!(
        stats.cancel_transfer_count, 0,
        "a completed download must not emit OP_CANCELTRANSFER (ADR-0056)"
    );
}

/// A link that names its own source (ADR-0089's amendment) is fed by it:
/// with no server session at all and Kad off, the run neither waits for a
/// connection nor fails its lookup — it dials the link's peer first and the
/// file arrives whole.
#[tokio::test]
async fn a_link_naming_its_source_downloads_with_no_server() {
    let bytes = b"a link that carries its own source".to_vec();
    let bare = file_link("linked.bin", &bytes);
    let peer = FakePeer::bind().await;
    let at = peer.addr();
    let peer_task = peer.spawn(PeerScript::serving(bare.file_hash, bytes.clone()));
    let canonical = Ed2kLink::File(bare).to_string();
    let text = format!("{}sources,{at}|/", canonical.strip_suffix('/').unwrap());
    let Ok(Ed2kLink::File(file)) = Ed2kLink::parse(&text) else {
        panic!("the link with its source stands: {text}");
    };
    assert_eq!(file.sources.peers().len(), 1, "{text}");

    let out = tempfile::tempdir().unwrap();
    let output_path = out.path().join("linked.bin");
    let mut core = Core::new(CoreConfig::default(), rmule_testkit::memory_store());
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: None,
        credentials: identity().into(),
        output_path: output_path.clone(),
    }))
    .await
    .unwrap();

    loop {
        let event = timeout(Duration::from_secs(10), core.next_event())
            .await
            .expect("core emitted event")
            .expect("core event stream stayed open");
        match event {
            CoreEvent::Download(DownloadEvent::WaitingForConnection { .. }) => {
                panic!("a link-fed run waited for a server")
            }
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. }) => break,
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("download failed: {reason:?}")
            }
            _ => {}
        }
    }
    assert_eq!(std::fs::read(&output_path).unwrap(), bytes);
    core.shutdown().await;
    let _ = timeout(Duration::from_secs(5), peer_task).await;
}

#[tokio::test]
async fn core_download_completes_from_a_real_serving_core() {
    // The happy-path half of the both-fakes policy (ADR-0040): the
    // counterparty is a second rmule core actually sharing the file through
    // the production ServeTask, so every step of the requester's flow runs
    // against the real serve side instead of a script. It is also the
    // two-sided byte-accounting proof (ADR-0077): one file crosses one wire,
    // so the puller's session down total and the server's session up total
    // must both equal the file, counted independently at each end.
    let _tracing = rmule_testkit::init_tracing();
    let bytes = vec![0xC7_u8; 4096];
    let file = file_link("loopback.bin", &bytes);

    let server = FakeEd2kServer::start_scripted().await;
    let mut serving = ServingCore::spawn(0x77, "served.bin", &bytes).await;
    server.set_sources(vec![serving.source()]).await;

    // The durable repository writes the finished file to disk, so the assert
    // below reads the bytes back out of the filesystem — the same Core shape
    // the operator CLI uses.
    let out = tempfile::tempdir().unwrap();
    let output_path = out.path().join("from-real-serve.bin");
    let mut core = Core::new(CoreConfig::default(), rmule_testkit::memory_store());
    rmule_testkit::connect_to(&core, &server.endpoint(), identity_with_port(0).into()).await;
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: Some(server.endpoint()),
        credentials: identity().into(),
        output_path: output_path.clone(),
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

    assert_eq!(
        std::fs::read(&output_path).unwrap(),
        bytes,
        "the file served by the real core arrived byte-for-byte"
    );
    assert_eq!(
        core.diagnostics_snapshot().session.down_bytes_total,
        bytes.len() as u64,
        "the puller counted every payload byte it took off the wire",
    );
    assert_eq!(
        serving
            .core_mut()
            .diagnostics_snapshot()
            .session
            .up_bytes_total,
        bytes.len() as u64,
        "the server counted the same bytes on the sending side",
    );
    drop(serving);
}

#[tokio::test]
async fn global_discovery_rescues_a_download_with_no_connected_server_source() {
    // Global-discovery rescue (ADR-0051): the connected server returns NO sources, but a managed
    // server answers over UDP. The download WAITS (WaitingForSources) instead of
    // failing NoUsableSources, the UDP-discovered High-ID peer is dialed, and the
    // part verifies — the end-to-end server-UDP discovery path, deterministic.
    let bytes = b"global source rescue download".to_vec();
    let file = file_link("loopback.bin", &bytes);
    let file_hash = file.file_hash;

    // The connected server logs rmule in (High-ID) but answers GetSources EMPTY:
    // without UDP discovery this download would fail NoUsableSources.
    let server = FakeEd2kServer::start_scripted().await;

    // The mock peer (the High-ID source delivered over UDP) serves the one part.
    let peer = FakePeer::bind().await;
    let udp = FakeServerUdp::start(file_hash, vec![peer.source()]).await;
    let peer_task = peer.spawn(PeerScript::serving(file_hash, bytes));

    // Short sweep interval so discovery fires promptly in the test.
    let config = CoreConfig {
        global_source_interval: Duration::from_millis(50),
        ..CoreConfig::default()
    };
    let mut core = Core::new(config, rmule_testkit::memory_store());

    // Arm global discovery with the UDP server, then start the download. Commands
    // are processed in order, so the server list is set before the download reads
    // it (→ global_discovery_active = true). The managed list holds the server's TCP
    // port; rmule's send adapter adds the eD2k +4 server-UDP offset, so configure
    // (bound UDP port − 4) to land back on the fake server's socket.
    crate::fixture::list_server(
        &core,
        &ServerEndpoint::parse_host_port(&format!("127.0.0.1:{}", udp.local_addr().port() - 4))
            .unwrap(),
    )
    .await;

    let out = tempfile::tempdir().unwrap();
    rmule_testkit::connect_to(&core, &server.endpoint(), identity_with_port(0).into()).await;
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: Some(server.endpoint()),
        credentials: identity().into(),
        output_path: out.path().join("rescue.bin"),
    }))
    .await
    .unwrap();

    let mut saw_waiting = false;
    let mut saw_peer = false;
    loop {
        let event = timeout(Duration::from_secs(10), core.next_event())
            .await
            .expect("core emitted event")
            .expect("core event stream stayed open");
        match event {
            CoreEvent::Download(DownloadEvent::WaitingForSources { .. }) => saw_waiting = true,
            CoreEvent::Download(DownloadEvent::PeerSelected { .. }) => saw_peer = true,
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. }) => break,
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("download failed: {reason:?}")
            }
            _ => {}
        }
    }
    assert!(
        saw_waiting,
        "WaitingForSources emitted: armed download with no connected-server source"
    );
    assert!(
        saw_peer,
        "PeerSelected for the UDP-discovered High-ID source"
    );

    // Serving keeps the dialed link open for uploads (ADR-0031);

    // the peer script ends when the core does.

    core.shutdown().await;

    let _ = peer_task.await;
}

#[tokio::test]
async fn core_completes_two_part_download_across_two_loopback_peers() {
    let part_size = rmule_primitives::ED2K_PART_SIZE;
    let mut bytes = vec![0xAB; part_size as usize];
    bytes.extend_from_slice(b"tail");
    let file = file_link("loopback.bin", &bytes);
    let file_hash = file.file_hash;
    let part_hashes = file.part_hash_set.as_ref().unwrap().hashes().to_vec();

    let server = FakeEd2kServer::start_scripted().await;
    let peer_a = FakePeer::bind().await;
    let peer_b = FakePeer::bind().await;
    server
        .set_sources(vec![peer_a.source(), peer_b.source()])
        .await;
    let full_script = |bytes: Vec<u8>| PeerScript {
        hash_set: HashSetPolicy::Parts(part_hashes.clone()),
        ..PeerScript::serving(file_hash, bytes)
    };
    let peer_a_task = peer_a.spawn(full_script(bytes.clone()));
    let peer_b_task = peer_b.spawn(full_script(bytes.clone()));

    let _tracing = rmule_testkit::init_tracing();
    let out = tempfile::tempdir().unwrap();
    let mut core = Core::new(CoreConfig::default(), rmule_testkit::memory_store());
    rmule_testkit::connect_to(&core, &server.endpoint(), identity_with_port(0).into()).await;
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: Some(server.endpoint()),
        credentials: identity().into(),
        output_path: out.path().join("two-peer.bin"),
    }))
    .await
    .unwrap();

    let mut verified_indexes = std::collections::HashSet::new();
    let mut assigned_indexes = std::collections::HashSet::new();
    // Part indexes the *level* surface reported verified positionally
    // (ADR-0079), gathered across the run to cross-check against the edge
    // surface's `PartVerified` indexes below.
    let mut level_verified_indexes = std::collections::HashSet::new();
    let mut mid_download_snapshot_captured = false;
    loop {
        let event = timeout(Duration::from_secs(10), core.next_event())
            .await
            .expect("core emitted event")
            .expect("core event stream stayed open");
        match event {
            CoreEvent::Download(DownloadEvent::PartAssigned { part_index, .. }) => {
                assigned_indexes.insert(part_index);
            }
            CoreEvent::Download(DownloadEvent::PartVerified { part_index, .. }) => {
                let snapshot = core.diagnostics_snapshot();
                if let Some(dd) = snapshot.downloads.values().next() {
                    // The part map spans the whole file while the download
                    // runs — a two-part file is two entries, indexed 0 and 1
                    // (ADR-0079), never a shrinking "remaining" list.
                    assert_eq!(
                        dd.parts.len(),
                        2,
                        "mid-download part map must cover every part of the file",
                    );
                    assert_eq!(
                        dd.part_counts().total() as usize,
                        dd.parts.len(),
                        "counts are a tally of the vector, so they span it exactly",
                    );
                    for (index, state) in dd.parts.iter().enumerate() {
                        if *state == PartState::Verified {
                            level_verified_indexes.insert(index as u32);
                        }
                    }
                }
                if !mid_download_snapshot_captured {
                    assert_eq!(
                        snapshot.downloads.len(),
                        1,
                        "active download must be present in diagnostics snapshot",
                    );
                    let dd = snapshot.downloads.values().next().unwrap();
                    assert!(
                        !dd.workers.is_empty(),
                        "active download must have at least one worker entry mid-download",
                    );
                    assert!(
                        dd.workers
                            .values()
                            .any(|entry| entry.transition_count() > 0),
                        "at least one worker must have transitioned away from Idle by part-verified time",
                    );
                    mid_download_snapshot_captured = true;
                }
                verified_indexes.insert(part_index);
            }
            CoreEvent::Download(DownloadEvent::DownloadCompleted { .. }) => break,
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("download failed: {reason:?}")
            }
            _ => {}
        }
    }
    assert!(
        mid_download_snapshot_captured,
        "expected at least one PartVerified before completion"
    );
    assert!(verified_indexes.contains(&0));
    assert!(verified_indexes.contains(&1));
    assert!(assigned_indexes.contains(&0));
    assert!(assigned_indexes.contains(&1));
    // Level and edge tell the same story about the same part indexes: every
    // part the snapshot showed Verified is one the event stream reported
    // verified (ADR-0079 — the map is the scheduler's own partition, not a
    // second opinion about progress).
    assert!(
        level_verified_indexes.is_subset(&verified_indexes),
        "part map claimed parts {level_verified_indexes:?} verified, events reported {verified_indexes:?}",
    );

    // Serving keeps the dialed link open for uploads (ADR-0031);

    // the peer script ends when the core does.

    core.shutdown().await;

    let _ = peer_a_task.await;
    let _ = peer_b_task.await;
}

#[tokio::test]
async fn core_download_fetches_single_part_in_multiple_blocks() {
    // A single-part file larger than EMBLOCKSIZE must be fetched as a
    // sequence of `<= EMBLOCKSIZE` OP_REQUESTPARTS blocks: a real peer
    // grants the upload slot but sends nothing for an over-large
    // whole-part request. The FakePeer Blocks policy enforces that exact
    // contract, so an unchunked worker stalls and only a block-chunking
    // worker completes the download.
    let block = rmule_peer::EMBLOCKSIZE as usize;
    let mut bytes = vec![0u8; block * 2 + 5000];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let file = file_link("loopback.bin", &bytes);
    let file_hash = file.file_hash;

    let server = FakeEd2kServer::start_scripted().await;
    let peer = FakePeer::bind().await;
    server.set_sources(vec![peer.source()]).await;
    // Single chunk relative to ED2K_PART_SIZE -> zero-part hash set.
    let peer_task = peer.spawn(PeerScript::serving(file_hash, bytes));

    let out = tempfile::tempdir().unwrap();
    let mut core = Core::new(CoreConfig::default(), rmule_testkit::memory_store());
    rmule_testkit::connect_to(&core, &server.endpoint(), identity_with_port(0).into()).await;
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: Some(server.endpoint()),
        credentials: identity().into(),
        output_path: out.path().join("multiblock.bin"),
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

    // Serving keeps the dialed link open for uploads (ADR-0031);

    // the peer script ends when the core does.

    core.shutdown().await;

    let stats = peer_task.await.unwrap();
    assert!(
        stats.max_block > 0 && stats.max_block <= rmule_peer::EMBLOCKSIZE,
        "worker must request the part in <= EMBLOCKSIZE blocks (largest was {})",
        stats.max_block
    );
    assert_eq!(
        stats.start_upload_count, 1,
        "one slot serves the whole multi-block part (exactly one OP_STARTUPLOADREQ)"
    );
}
