//! A link rmule dialed notes what it shows of its far end (ADR-0107
//! invariant 7): the serve side reads it before it lets the client's own link
//! go for the dial, so a reset read on the dial must show at once, before its
//! close reaches the serve side.

use super::*;

#[tokio::test]
async fn a_dialed_link_the_peer_resets_reads_dead_at_its_far_end() {
    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let bound = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_port());
    let (drop_tx, drop_rx) = tokio::sync::oneshot::channel::<()>();
    let _peer = tokio::spawn(async move {
        let conn = listener
            .accept(dialed_serve_ctx(), PeerConnectOptions::default())
            .await
            .unwrap();
        let _ = drop_rx.await;
        drop(conn);
    });

    let (dialed_tx, mut dialed_rx) = mpsc::channel(4);
    let sink = SharedDialedServeSink::default();
    sink.install_for_good(dialed_tx);
    let mut transfer =
        RuntimePeerTransferService::with_dialed_serve_sink(crate::DEFAULT_SLOT_WAIT_TIMEOUT, sink);
    let peer = PeerEndpoint::V4(Ipv4Endpoint::new(*bound.ip(), bound.port()));
    let _worker = transfer
        .start_peer_worker(peer, dialed_serve_ctx(), dummy_file(0x7A))
        .await
        .unwrap();
    let half = timeout(Duration::from_secs(5), dialed_rx.recv())
        .await
        .expect("the dialed link's serve half reaches the serve side")
        .expect("a serve connection");
    let far_end = half.dialed.expect("a link rmule dialed reads its far end");
    let mut serve_conn = half.conn;
    assert_eq!(
        far_end.dead_at(std::time::Instant::now()),
        None,
        "alive while the peer holds it"
    );

    drop_tx.send(()).unwrap();
    let closed = timeout(Duration::from_secs(5), async {
        while let Some(input) = serve_conn.next_event().await {
            if input.is_disconnect() {
                return true;
            }
        }
        false
    })
    .await;
    assert_eq!(closed, Ok(true), "the close reaches the serve side");
    assert_eq!(
        far_end.dead_at(std::time::Instant::now()),
        Some(crate::service::DeadDialSign::Ended),
        "the far end read dead no later than the serve side heard the close"
    );
}
