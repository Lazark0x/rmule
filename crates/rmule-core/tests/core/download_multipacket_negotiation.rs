//! The download's connect-time file negotiation, both halves of the MultiPacket gate:
//! toward an uploader advertising MultiPacket it goes out as one
//! `OP_MULTIPACKET_EXT` bundle (`0x58` name + `0x4F` status + `0x83` SX2 ask)
//! with no standalone probes, and toward a pre-MultiPacket uploader as exactly
//! the standalone `0x58` + `0x4F` pair — completing identically either way.

use crate::fixture::identity_with_port;
use std::time::Duration;

use crate::fixture::identity;
use rmule_core::{Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand, DownloadEvent};
use rmule_peer::PartBitmap;
use rmule_primitives::ED2K_PART_SIZE;
use rmule_testkit::{
    FakeEd2kServer, FakePeer, HashSetPolicy, MultiPacketPolicy, PeerScript, SeenMultiPacketRequest,
    file_link,
};
use tokio::time::timeout;

#[tokio::test]
async fn the_live_download_folds_its_file_request_into_an_0xa4_bundle_for_an_ext_peer() {
    // The live download runner's connect-time file
    // negotiation reaches a MultiPacket-advertising uploader as ONE
    // `OP_MULTIPACKET_EXT` bundle — `0x58` name + `0x4F` status + `0x83` SX2
    // ask, `size8` = the file size — with zero standalone probe packets, and
    // the download completes through the peer's composed `0x93` answer.
    // Multi-part on purpose: the bundle fold is the multi-part connect shape
    // (a sub-part file keeps the granular path).
    let bytes = vec![0x5C_u8; (ED2K_PART_SIZE + 4096) as usize];
    let file = file_link("loopback.bin", &bytes);
    let file_hash = file.file_hash;
    let file_size = file.size;
    let part_hashes = file
        .part_hash_set
        .clone()
        .expect("a multi-part file carries its hash set")
        .hashes()
        .to_vec();

    let server = FakeEd2kServer::start_scripted().await;
    let peer = FakePeer::bind().await;
    server.set_sources(vec![peer.source()]).await;
    let peer_task = peer.spawn(PeerScript {
        multipacket: MultiPacketPolicy::AnswerBundle,
        hash_set: HashSetPolicy::Parts(part_hashes),
        ..PeerScript::serving(file_hash, bytes)
    });

    let out = tempfile::tempdir().unwrap();
    let mut core = Core::new(CoreConfig::default(), rmule_testkit::memory_store());
    rmule_testkit::connect_to(&core, &server.endpoint(), identity_with_port(0).into()).await;
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: Some(server.endpoint()),
        credentials: identity().into(),
        output_path: out.path().join("bundled-negotiation.bin"),
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

    let stats = timeout(Duration::from_secs(5), peer_task)
        .await
        .expect("peer script finished after the download wound down")
        .unwrap();
    assert_eq!(
        stats.multipacket_request,
        Some(SeenMultiPacketRequest {
            opcode: 0xA4,
            size8: Some(file_size),
            sub_opcodes: vec![0x58, 0x4F, 0x83],
            name_status: Some(PartBitmap::downloader_empty(file_size)),
        }),
        "the live runner's connect negotiation is one 0xA4 bundle: name (carrying \
         what the download holds) + status + SX2 ask"
    );
    assert_eq!(
        stats.standalone_probe_asks, 0,
        "the bundle replaced the standalone 0x58/0x4F probe pair on the live path"
    );
}

#[tokio::test]
async fn a_multi_part_download_against_a_pre_multipacket_peer_keeps_the_standalone_probes() {
    // The MultiPacket gate's other half: the same multi-part connect negotiation
    // toward an uploader that advertised no MultiPacket capability goes out
    // as the separate standalone packets — exactly one 0x58 + one 0x4F, no
    // bundle on the wire — and the download completes identically.
    let bytes = vec![0x6D_u8; (ED2K_PART_SIZE + 4096) as usize];
    let file = file_link("loopback.bin", &bytes);
    let file_hash = file.file_hash;
    let part_hashes = file
        .part_hash_set
        .clone()
        .expect("a multi-part file carries its hash set")
        .hashes()
        .to_vec();

    let server = FakeEd2kServer::start_scripted().await;
    let peer = FakePeer::bind().await;
    server.set_sources(vec![peer.source()]).await;
    let peer_task = peer.spawn(PeerScript {
        hash_set: HashSetPolicy::Parts(part_hashes),
        ..PeerScript::serving(file_hash, bytes)
    });

    let out = tempfile::tempdir().unwrap();
    let mut core = Core::new(CoreConfig::default(), rmule_testkit::memory_store());
    rmule_testkit::connect_to(&core, &server.endpoint(), identity_with_port(0).into()).await;
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file,
        source_hint: Some(server.endpoint()),
        credentials: identity().into(),
        output_path: out.path().join("standalone-negotiation.bin"),
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

    let stats = timeout(Duration::from_secs(5), peer_task)
        .await
        .expect("peer script finished after the download wound down")
        .unwrap();
    assert!(
        stats.multipacket_request.is_none(),
        "no MultiPacket advert ⇒ no bundle on the wire"
    );
    assert_eq!(
        stats.standalone_probe_asks, 2,
        "the standalone probe pair (0x58 + 0x4F) went out exactly once at connect"
    );
}
