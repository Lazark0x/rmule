//! The run's source-exchange pool (ADR-0113, aMule `PartFile.cpp:2596-2605`):
//! the sources we download from or wait at, a full queue left out.

use rmule_primitives::PeerSource;

use super::*;

#[test]
fn the_pool_holds_what_we_download_from_or_wait_at_and_leaves_out_a_full_queue() {
    let pool = [peer(1), peer(2), peer(3), peer(4)];
    let mut state = pooled_state(
        file_hash_only_content(THREE_PARTS),
        &pool,
        live_posture(),
        pool.len(),
    );
    let _ = state.start(t0());
    queue_and_hang_up(&mut state, peer(1), true, 5);
    queue_and_hang_up(&mut state, peer(2), true, 6);
    // peer(3) works a part; peer(4) is still being dialled.
    let _ = connect(&mut state, t0(), peer(3));
    let window = t0() + udp_due();
    let _ = state.on_tick(window);
    let middle = PartBitmap::decode(3, &[0b0000_0010]).expect("three parts");
    let _ = state.on_reask_reply(window, contact(peer(1)), &v4_ack_with(middle.clone(), 2));
    let _ = state.on_reask_reply(window, contact(peer(2)), &queue_full_datagram());

    let at = |n| match peer(n) {
        PeerEndpoint::V4(v4) => PeerSource::HighId(v4),
        PeerEndpoint::V6(_) => unreachable!("an IPv4 test peer"),
    };
    let exchange = state.exchange_pool();
    assert_eq!(
        exchange.sources,
        [
            (SourceSighting::new(at(1), Some(SOURCE), None), Some(middle)),
            (
                SourceSighting::new(at(3), None, None),
                Some(PartBitmap::all_present(3))
            ),
        ]
    );
    assert_eq!(exchange.known, 4, "every source counts toward rarity");
}
