//! Reverse-harness round-trip for the ADR-0054 bundle **emit** direction
//! Rmule dials as the downloader; against a `FakePeer`
//! uploader that advertised MultiPacket it folds its file-request quintet into
//! one `OP_MULTIPACKET_EXT` bundle. The uploader answers a single `0x93`, and
//! rmule surfaces `FileProbed { Available }` — the counterparty's *acceptance*
//! (ADR-0045 emit-evidence: reaction, not transmission), standing in the
//! deterministic tier for a real aMule proceeding into upload negotiation.

use std::time::Duration;

use crate::fixture::peer_endpoint;
use rmule_net::peer::{ConnectOptions, Connection};
use rmule_peer::{
    ConnectionEvent, FileProbeStatus, PeerCommand, PeerEvent, RequesterCommand, RequesterEvent,
};
use rmule_primitives::{ED2K_PART_SIZE, FileHash, UserHash};
use rmule_testkit::peer_session::loopback_ctx;
use rmule_testkit::{FakePeer, MultiPacketPolicy, PeerScript};

#[tokio::test]
async fn request_file_bundles_against_a_multipacket_uploader_and_probes_available() {
    let file_hash = FileHash::from_bytes([0x5A; FileHash::BYTE_LEN]);
    let peer = FakePeer::bind().await;
    let endpoint = peer_endpoint(peer.addr());

    // The uploader advertises MultiPacket + ExtMultiPacket and answers a bundle
    // with one composed 0x93.
    let script = PeerScript {
        multipacket: MultiPacketPolicy::AnswerBundle,
        file_name: "reverse-harness.bin".into(),
        hello_user_hash: UserHash::from_bytes([0xBE; UserHash::BYTE_LEN]),
        ..PeerScript::serving(file_hash, Vec::new())
    };
    let peer_task = peer.spawn(script);

    let options = ConnectOptions {
        connect_timeout: Duration::from_secs(2),
        hello_timeout: Duration::from_secs(5),
        capture_dir: None,
        ..Default::default()
    };
    let mut conn = Connection::connect(endpoint, loopback_ctx(), options)
        .await
        .expect("connect");

    // Identify first, so the peer's multipacket advert is read before we ask —
    // the emit gate reads `peer_misc_options`/`peer_misc_options2`.
    loop {
        match conn.next_event().await {
            Some(PeerEvent::Connection(ConnectionEvent::Identified { .. })) => break,
            Some(_) => {}
            None => panic!("connection closed before identify"),
        }
    }

    conn.send(PeerCommand::Requester(RequesterCommand::RequestFile {
        file_hash,
        file_size: ED2K_PART_SIZE + 1,
        own_status: rmule_peer::PartBitmap::downloader_empty(ED2K_PART_SIZE + 1), // multi-part → the bundle carries Name + SetReqId
        want_sources: false,
        want_aich_root: false,
    }))
    .await
    .expect("send RequestFile");

    let mut probed = None;
    while let Some(event) = conn.next_event().await {
        if let PeerEvent::Requester(RequesterEvent::FileProbed {
            file_hash: fh,
            status,
        }) = event
            && fh == file_hash
        {
            probed = Some(status);
            break;
        }
    }
    match probed.expect("the uploader's 0x93 upgraded probe state to Available") {
        FileProbeStatus::Available { file_name, .. } => {
            assert_eq!(file_name.to_display_string(), "reverse-harness.bin");
        }
        other => panic!("expected Available, got {other:?}"),
    }

    conn.shutdown().await.expect("shutdown");
    let stats = peer_task.await.expect("peer script finished");
    // Pin the wire shape, not just the downstream probe upgrade: the fake
    // answers standalone probes too, so `FileProbed { Available }` alone
    // cannot prove a bundle went out (an earlier testkit hello with a dead
    // advert let exactly that vacuity slip through).
    let seen = stats
        .multipacket_request
        .expect("the request arrived as a multipacket bundle, not standalone packets");
    assert_eq!(seen.opcode, 0xA4, "ext advert selects the 0xA4 frame");
    assert_eq!(
        seen.sub_opcodes,
        vec![0x58, 0x4F],
        "multi-part, no SX/AICH wants: the bundle carries name + status asks"
    );
}
