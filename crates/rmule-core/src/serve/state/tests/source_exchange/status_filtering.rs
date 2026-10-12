//! Source-exchange answers filtered by the asker's part status: sources holding
//! only parts the asker has are left out, unknown statuses are kept.

use super::*;

#[test]
fn a_source_holding_only_parts_the_asker_has_is_left_out_of_its_answer() {
    let file = hash(0x55);
    let size = 2 * ED2K_PART_SIZE + 1_000;
    let t = Instant::now();
    let (mut state, [_a, b, c, _d]) = pool_with_known_unknown_and_empty_status(file, size, t);

    // An asker holding part 0: `a` holds only part 0 and `d` nothing, so
    // both are left out; `b` holds part 1 the asker lacks; `c`'s parts are
    // unknown and it is sent (aMule's "send it and hope").
    let asker = peer_at([8, 8, 8, 8], 4000);
    identify_source(
        &mut state,
        asker,
        user(0xD4),
        high_id_client([8, 8, 8, 8]),
        4662,
        t,
    );
    let holds_part_0 = PartBitmap::downloader(size, |i| i.value() == 0);
    name_ask(&mut state, asker, file, Some(holds_part_0), t);
    assert_eq!(
        answered(&mut state, asker, file, t),
        vec![b, c],
        "only the sources offering a part the asker lacks",
    );
}

#[test]
fn an_asker_without_a_readable_status_is_sent_sources_holding_a_part_and_the_unknowns() {
    let file = hash(0x56);
    // An exact multiple, so every wire status counts a phantom third part the
    // writer sets: only the two real parts may count as held.
    let size = 2 * ED2K_PART_SIZE;
    let t = Instant::now();
    let (mut state, [a, b, c, _d]) = pool_with_known_unknown_and_empty_status(file, size, t);

    // A v0 claimant's ask carries no status; a v1 claimant's status at a
    // count this file does not have is dropped as aMule drops it. Either is
    // answered aMule's rule for an asker without chunk status (ADR-0055 divergence 1):
    // the sources holding a part and the unknown `c`,
    // never `d`, whose own ask said it holds nothing.
    let mismatched = PartBitmap::downloader(ED2K_PART_SIZE + 1, |_| true);
    for (octets, status) in [([8, 8, 8, 8], None), ([9, 9, 9, 9], Some(mismatched))] {
        let asker = peer_at(octets, 4000);
        identify_source(
            &mut state,
            asker,
            user(0xD4),
            high_id_client(octets),
            4662,
            t,
        );
        name_ask(&mut state, asker, file, status, t);
        assert_eq!(answered(&mut state, asker, file, t,), vec![a, b, c],);
    }
}

#[test]
fn a_waiters_udp_reask_restates_the_parts_its_source_answer_is_filtered_by() {
    let file = hash(0x57);
    let size = 2 * ED2K_PART_SIZE + 1_000;
    let holding = |parts: &[u32]| PartBitmap::downloader(size, |i| parts.contains(&i.value()));
    let t = Instant::now();
    let mut state = serving_state(2, vec![entry(file, size, "served.bin")]);

    // Two granted sources, one holding part 1 and one part 2.
    let mut granted = Vec::new();
    for (octets, hash_byte, part) in [([1, 2, 3, 4], 0xA1, 1), ([5, 6, 7, 8], 0xB2, 2)] {
        let p = peer_at(octets, 4000);
        identify_source(
            &mut state,
            p,
            user(hash_byte),
            high_id_client(octets),
            4662,
            t,
        );
        name_ask(&mut state, p, file, Some(holding(&[part])), t);
        let _ = slot_request(&mut state, p, file, t);
        granted.push(rmule_primitives::SourceSighting::new(
            PeerSource::new(high_id_client(octets), 4662),
            Some(user(hash_byte)),
            None,
        ));
    }

    // A UDPv4 waiter whose name ask said it holds nothing, queued behind them.
    let waiter = peer_at([10, 0, 0, 2], 4000);
    let _ = state.on_conn_event(
        t,
        waiter,
        HelloFacts {
            client_id: high_id_client([10, 0, 0, 2]),
            udp_port: 6000,
            udp_version: 4,
            ..HelloFacts::of(user(0x0A))
        }
        .identified(),
        &no_modifiers(),
    );
    name_ask(&mut state, waiter, file, Some(holding(&[])), t);
    let _ = slot_request(&mut state, waiter, file, t);

    // Its UDP reask says it has since completed part 1 (aMule hands the ping
    // to the name ask's reader, `ClientUDPSocket.cpp:202-203`).
    let ping = ReaskFilePing {
        file_hash: file,
        part_status: Some(holding(&[1])),
        complete_sources: Some(0),
    }
    .encode_udp();
    assert!(matches!(
        state
            .on_reask_ping(t, udp([10, 0, 0, 2], 6000), &ping)
            .as_slice(),
        [ServeDecision::SendClientUdp { .. }],
    ));

    // Its own source answer now leaves out the part-1 source; on its name
    // ask's status alone it would have been sent both.
    assert_eq!(answered(&mut state, waiter, file, t,), vec![granted[1]],);
}
