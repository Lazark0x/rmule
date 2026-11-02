//! Peer inbound packed (`0xD4`) frame loopback (ADR-0053, Correctness
//! Tier): `FakePeer` answers `OP_REQUESTSOURCES` with a packed
//! `OP_ANSWERSOURCES`, and the live session over a real TCP connection
//! inflates it to `RequesterEvent::SourcesReceived` — the wire-level companion to
//! `rmule-peer`'s `session_compressed_frames.rs` unit vectors.

use std::time::Duration;

use crate::fixture::peer_endpoint;
use rmule_net::peer::{ConnectOptions, Connection};
use rmule_peer::{ConnectionEvent, PeerCommand, PeerEvent, RequesterCommand, RequesterEvent};
use rmule_primitives::{ClientId, FileHash, Informant, PeerSource, SourceClaim, UserHash};
use rmule_testkit::peer_session::loopback_ctx;
use rmule_testkit::{FakePeer, PeerScript, SourcesPolicy};

#[tokio::test]
async fn packed_answer_sources_inflates_to_sources_received_over_real_connection() {
    let peer = FakePeer::bind().await;
    let endpoint = peer_endpoint(peer.addr());
    let file_hash = FileHash::from_bytes([0x21; 16]);
    // The fake claims SX1 v2 — the lowest version aMule asks (ADR-0108) — and
    // a v2 entry always carries its source's User Hash.
    let source_hash = UserHash::from_bytes([
        0x13, 0x57, 0x9B, 0xDF, 0x24, 0x68, 0xAC, 0xE0, 0x31, 0x75, 0xB9, 0xFD, 0x42, 0x86, 0xCA,
        0x0E,
    ]);
    let sources: Vec<SourceClaim> = (0..20)
        .map(|_| {
            SourceClaim::new(
                PeerSource::new(ClientId::from_u32(0xC0A8_0101), 4662),
                Some(source_hash),
                None,
            )
        })
        .collect();

    let mut script = PeerScript::hello_only(
        UserHash::from_bytes([0xBE; UserHash::BYTE_LEN]),
        "loopback-peer",
    );
    script.sources = SourcesPolicy::AnswerPacked(sources.clone());
    let peer_task = peer.spawn(script);

    let options = ConnectOptions {
        connect_timeout: Duration::from_secs(2),
        hello_timeout: Duration::from_secs(5),
        ..Default::default()
    };
    let mut conn = Connection::connect(endpoint, loopback_ctx(), options)
        .await
        .expect("connect");

    let mut identified = false;
    while let Some(event) = conn.next_event().await {
        if matches!(
            event,
            PeerEvent::Connection(ConnectionEvent::Identified { .. })
        ) {
            identified = true;
            break;
        }
    }
    assert!(identified, "Identified arrived");

    conn.send(PeerCommand::Requester(RequesterCommand::RequestSources {
        file_hash,
    }))
    .await
    .expect("send RequestSources");

    let mut received = None;
    while let Some(event) = conn.next_event().await {
        if let PeerEvent::Requester(RequesterEvent::SourcesReceived { file_hash, sources }) = event
        {
            received = Some((file_hash, sources));
            break;
        }
    }
    let (received_hash, received_sources) = received.expect("SourcesReceived arrived");
    assert_eq!(received_hash, file_hash);
    assert_eq!(received_sources.len(), sources.len());
    let answerer = Informant::Party(endpoint.ip());
    let stated: Vec<_> = sources
        .iter()
        .map(|sent| sent.stated_by(answerer))
        .collect();
    assert_eq!(
        received_sources, stated,
        "each is the answering peer's word"
    );

    conn.shutdown().await.expect("shutdown");
    let _ = peer_task.await;
}
