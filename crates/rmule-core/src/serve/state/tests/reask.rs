//! The uploader-side reask answers (ADR-0057): rank replies carrying our part
//! status for a UDPv4-era waiter, the not-found and queue-full refusals, the
//! silent drops, and the purge sweep a reask heartbeat saves a waiter from.

use super::*;

#[test]
fn a_matched_reask_answers_the_rank_with_our_part_status_for_a_udpv4_waiter() {
    let file = hash(0x11);
    let two_parts = ED2K_PART_SIZE + 1;
    let waiter = peer_at([10, 0, 0, 2], 4000);
    let t = Instant::now();
    let mut state = one_waiter_state(file, two_parts, waiter, 6000, 4, t);

    // A reask from the waiter's advertised UDP endpoint answers OP_REASKACK
    // with rank 1 and — since the peer is UDPv4 — our part status, in aMule's
    // shape for a complete file: the count `0` alone
    // (`ClientUDPSocket.cpp:214-219`).
    let src = udp([10, 0, 0, 2], 6000);
    assert_eq!(
        state.on_reask_ping(t, src, &reask_ping(file)),
        vec![ServeDecision::SendClientUdp {
            to: src,
            datagram: ReaskAck {
                part_status: Some(PartBitmap::complete_source_sentinel()),
                rank: 1,
            }
            .encode_udp(),
            // The resolved waiter's identity rides along, so the socket
            // boundary may obfuscate this ack (ADR-0046).
            crypt_target: target_of(user(0x0A)),
        }],
    );

    // Unique-IP fallback: a reask from a *different* UDP port of the same
    // IP still matches, since exactly one waiter shares that IP.
    let other_port = udp([10, 0, 0, 2], 9999);
    assert_eq!(
        state.on_reask_ping(t, other_port, &reask_ping(file)),
        vec![ServeDecision::SendClientUdp {
            to: other_port,
            datagram: ReaskAck {
                part_status: Some(PartBitmap::complete_source_sentinel()),
                rank: 1,
            }
            .encode_udp(),
            crypt_target: target_of(user(0x0A)),
        }],
    );
}

#[test]
fn a_reask_ack_omits_our_part_status_for_a_pre_udpv4_waiter() {
    let file = hash(0x22);
    let waiter = peer_at([10, 0, 0, 2], 4000);
    let t = Instant::now();
    // UDP version 3 (not > 3): no part status rides the ack.
    let mut state = one_waiter_state(file, 4096, waiter, 6000, 3, t);
    let src = udp([10, 0, 0, 2], 6000);
    assert_eq!(
        state.on_reask_ping(t, src, &reask_ping(file)),
        vec![ServeDecision::SendClientUdp {
            to: src,
            datagram: ReaskAck {
                part_status: None,
                rank: 1,
            }
            .encode_udp(),
            crypt_target: target_of(user(0x0A)),
        }],
    );
}

/// A UDPv3 waiter's ping is read for its complete-source count
/// right after the hash, whatever its extended-requests claim (stock 2.3.3
/// `4e8f2b3c` `ClientUDPSocket.cpp:204-205`); the hash alone makes that read
/// throw, the dispatcher only logs (`:131-134`), and nothing is sent.
#[test]
fn a_hash_only_udpv3_ping_is_silenced() {
    let file = hash(0x23);
    let waiter = peer_at([10, 0, 0, 2], 4000);
    let t = Instant::now();
    let mut state = one_waiter_state(file, 4096, waiter, 6000, 3, t);
    assert_eq!(
        state.on_reask_ping(t, udp([10, 0, 0, 2], 6000), &hash_only_ping(file)),
        vec![ServeDecision::Emit(ServeEvent::ReaskPingMalformed {
            peer: waiter
        })],
    );
}

/// A UDPv4 waiter's ping carrying the file hash alone. aMule's
/// reader returns before looking at it for a peer whose hello claimed
/// extended requests `0` (stock 2.3.3 `UploadClient.cpp:403-406`), so that
/// peer is answered; from any other it throws (`:408-412`), its dispatcher
/// only logs (`ClientUDPSocket.cpp:131-132`), and nothing is sent.
#[test]
fn a_hash_only_udpv4_ping_is_silenced_only_from_a_peer_claiming_extended_requests() {
    let file = hash(0x33);
    let waiter = peer_at([10, 0, 0, 2], 4000);
    let src = udp([10, 0, 0, 2], 6000);
    let t = Instant::now();

    let mut claimant = one_waiter_state(file, 4096, waiter, 6000, 4, t);
    assert_eq!(
        claimant.on_reask_ping(t, src, &hash_only_ping(file)),
        vec![ServeDecision::Emit(ServeEvent::ReaskPingMalformed {
            peer: waiter
        })],
    );

    let mut v0 = serving_state(1, vec![entry(file, 4096, "served.bin")]);
    let _ = slot_request(&mut v0, peer_at([10, 0, 0, 1], 4000), file, t);
    identify_udp_claiming(&mut v0, waiter, user(0x0A), 6000, 4, 0, t);
    let _ = slot_request(&mut v0, waiter, file, t);
    assert_eq!(
        v0.on_reask_ping(t, src, &hash_only_ping(file)),
        vec![ServeDecision::SendClientUdp {
            to: src,
            datagram: ReaskAck {
                part_status: Some(PartBitmap::complete_source_sentinel()),
                rank: 1,
            }
            .encode_udp(),
            crypt_target: target_of(user(0x0A)),
        }],
    );
}

/// AMule's reader sizes the status by the file's part count and
/// reads the complete-source count after it only for a claim above `1`
/// (stock 2.3.3 `4e8f2b3c` `UploadClient.cpp:424-455`); a ping cut short of
/// either throws, and is silenced as the hash-only one is. The same ping
/// without the count is whole from a claim of `1`.
#[test]
fn a_udpv4_ping_short_of_its_status_or_complete_count_is_silenced() {
    let file = hash(0x34);
    let size = 2 * ED2K_PART_SIZE + 1; // three parts: one status byte
    let waiter = peer_at([10, 0, 0, 2], 4000);
    let src = udp([10, 0, 0, 2], 6000);
    let t = Instant::now();
    let ping = |tail: &[u8]| [hash_only_ping(file).as_slice(), tail].concat();
    let silenced = vec![ServeDecision::Emit(ServeEvent::ReaskPingMalformed {
        peer: waiter,
    })];

    // `one_waiter_state` identifies the waiter claiming extended requests 2.
    let mut claim_2 = one_waiter_state(file, size, waiter, 6000, 4, t);
    assert_eq!(
        claim_2.on_reask_ping(t, src, &ping(&[0x03, 0x00])),
        silenced
    );
    assert_eq!(
        claim_2.on_reask_ping(t, src, &ping(&[0x03, 0x00, 0x05])),
        silenced
    );

    let mut claim_1 = serving_state(1, vec![entry(file, size, "served.bin")]);
    let _ = slot_request(&mut claim_1, peer_at([10, 0, 0, 1], 4000), file, t);
    identify_udp_claiming(&mut claim_1, waiter, user(0x0A), 6000, 4, 1, t);
    let _ = slot_request(&mut claim_1, waiter, file, t);
    assert_eq!(
        claim_1.on_reask_ping(t, src, &ping(&[0x03, 0x00, 0x05])),
        vec![ServeDecision::SendClientUdp {
            to: src,
            datagram: ReaskAck {
                part_status: Some(PartBitmap::complete_source_sentinel()),
                rank: 1,
            }
            .encode_udp(),
            crypt_target: target_of(user(0x0A)),
        }],
    );
}

#[test]
fn a_reask_for_an_unshared_hash_answers_file_not_found() {
    let mut state = serving_state(1, vec![entry(hash(0x11), 4096, "served.bin")]);
    let t = Instant::now();
    let src = udp([10, 0, 0, 9], 6000);
    assert_eq!(
        state.on_reask_ping(t, src, &reask_ping(hash(0x99))),
        vec![ServeDecision::SendClientUdp {
            to: src,
            datagram: file_not_found_datagram(),
            // A stranger's ping: no identity, so no crypt target — plaintext.
            crypt_target: None,
        }],
    );
}

#[test]
fn a_known_waiters_file_not_found_still_carries_its_crypt_target() {
    // aMule resolves the *sender* before the file (`ClientUDPSocket.cpp`),
    // so even the "I don't share that" answer is obfuscated for a client it
    // knows — the ordering this row has to reproduce.
    let served = hash(0x11);
    let waiter = peer_at([10, 0, 0, 2], 4000);
    let t = Instant::now();
    let mut state = one_waiter_state(served, 4096, waiter, 6000, 4, t);
    let src = udp([10, 0, 0, 2], 6000);

    assert_eq!(
        state.on_reask_ping(t, src, &reask_ping(hash(0x99))),
        vec![ServeDecision::SendClientUdp {
            to: src,
            datagram: file_not_found_datagram(),
            crypt_target: target_of(user(0x0A)),
        }],
    );
}

#[test]
fn an_unknown_pinger_gets_queue_full_only_when_the_queue_is_nearly_full() {
    let file = hash(0x11);
    let t = Instant::now();
    let src = udp([10, 0, 0, 9], 6000);

    // Nearly-full queue (cap 8): 0 waiting + 50 > 8 → OP_QUEUEFULL.
    let mut nearly_full = serving_state(1, vec![entry(file, 4096, "served.bin")]);
    assert_eq!(
        nearly_full.on_reask_ping(t, src, &reask_ping(file)),
        vec![ServeDecision::SendClientUdp {
            to: src,
            datagram: queue_full_datagram(),
            // Never obfuscated: this branch *is* the unknown pinger (aMule:
            // "we cannot answer this one encrypted since we dont know this
            // client").
            crypt_target: None,
        }],
    );

    // Roomy queue (cap 100): 0 + 50 <= 100 → silent, forcing a TCP full ask.
    let mut roomy = ServeState::new(UploadSlotQueue::new(1, 100));
    let _ = roomy.on_share_set(
        vec![entry(file, 4096, "served.bin")],
        std::time::Instant::now(),
        &std::collections::HashMap::new(),
    );
    assert_eq!(roomy.on_reask_ping(t, src, &reask_ping(file)), Vec::new());
}

#[test]
fn a_hash_mismatch_and_a_port_mapping_ambiguity_are_silent_drops() {
    let served = hash(0x11);
    let other = hash(0x22);
    let mut state = ServeState::new(UploadSlotQueue::new(1, 100));
    let _ = state.on_share_set(
        vec![entry(served, 4096, "a.bin"), entry(other, 4096, "b.bin")],
        std::time::Instant::now(),
        &std::collections::HashMap::new(),
    );
    let t = Instant::now();
    let _ = slot_request(&mut state, peer_at([10, 0, 0, 1], 4000), served, t);

    // A known waiter queued for `other`, pinging for `served` → hash
    // mismatch → silent (forces a TCP full ask).
    let waiter = peer_at([10, 0, 0, 2], 4000);
    identify_udp(&mut state, waiter, user(0x0A), 6000, 4, t);
    let _ = slot_request(&mut state, waiter, other, t);
    let src = udp([10, 0, 0, 2], 6000);
    assert_eq!(state.on_reask_ping(t, src, &reask_ping(served)), Vec::new());
    // Its reask for the file it *is* queued for does answer.
    assert!(matches!(
        state.on_reask_ping(t, src, &reask_ping(other)).as_slice(),
        [ServeDecision::SendClientUdp { .. }]
    ));

    // Two waiters share one IP on different UDP ports; a ping from a third
    // port of that IP is the port-mapping ambiguity → silent.
    for (tcp, udp_port) in [(4000, 6001), (4001, 6002)] {
        let p = peer_at([10, 0, 0, 3], tcp);
        identify_udp(&mut state, p, user(0x0B), udp_port, 4, t);
        let _ = slot_request(&mut state, p, served, t);
    }
    let ambiguous = udp([10, 0, 0, 3], 6999);
    assert_eq!(
        state.on_reask_ping(t, ambiguous, &reask_ping(served)),
        Vec::new()
    );
}

#[test]
fn a_waiting_peer_keeps_its_position_across_disconnect_and_still_reasks() {
    let file = hash(0x11);
    let waiter = peer_at([10, 0, 0, 2], 4000);
    let t = Instant::now();
    let mut state = one_waiter_state(file, 4096, waiter, 6000, 4, t);

    // The waiter's TCP drops: the holder still holds the slot, so nothing
    // frees and no UploadSlotReleased fires — disconnected standing.
    assert_eq!(
        state.on_conn_event(t, waiter, ServeConnEvent::Disconnected, &no_modifiers()),
        Vec::new(),
    );
    // Its reask still answers rank 1 — the position survived the disconnect,
    // and so did its crypt target (a waiter keeping standing keeps both).
    let src = udp([10, 0, 0, 2], 6000);
    assert_eq!(
        state.on_reask_ping(t, src, &reask_ping(file)),
        vec![ServeDecision::SendClientUdp {
            to: src,
            datagram: ReaskAck {
                part_status: Some(PartBitmap::complete_source_sentinel()),
                rank: 1,
            }
            .encode_udp(),
            crypt_target: target_of(user(0x0A)),
        }],
    );
}

#[test]
fn promoting_a_disconnected_waiter_dials_back_rather_than_granting_over_a_dead_socket() {
    let file = hash(0x11);
    let waiter = peer_at([10, 0, 0, 2], 4000);
    let holder = peer_at([10, 0, 0, 1], 4000);
    let t = Instant::now();
    let mut state = one_waiter_state(file, 4096, waiter, 6000, 4, t);

    // The waiter loses its socket (keeps standing), then the holder frees
    // the slot: the sole waiter is promoted, but with no live connection it
    // is a dial-back grant, not a GrantSlot over a dead socket.
    let _ = state.on_conn_event(t, waiter, ServeConnEvent::Disconnected, &no_modifiers());
    assert_eq!(
        state.on_conn_event(t, holder, ServeConnEvent::Disconnected, &no_modifiers()),
        vec![
            ServeDecision::DialBackGrant {
                peer: waiter,
                file_hash: file,
            },
            ServeDecision::Emit(ServeEvent::UploadSlotGranted {
                peer: waiter,
                file_hash: file,
                // The waiter hung up, but its hello's identification waited
                // with it: the grant still names its client.
                software: Some(nameless_software()),
            }),
            ServeDecision::Emit(ServeEvent::UploadSlotReleased { peer: holder }),
        ],
    );
}

/// The live-consume regression: once a disconnected top-waiter
/// is promoted to a **pending dial-back grant** (the holder freed the slot,
/// the serve-dial is deferred), its own `OP_REASKFILEPING` must still earn an
/// `OP_REASKACK` at the head of the queue — not the silent drop that stranded
/// it for the whole `MAX_PURGEQUEUETIME`. The grant carries the waiter's
/// promoted UDP version, so this v4 grantee's ack includes our part status —
/// a rank-only reply would be unparseable at a v4 aMule (it reads the rank as
/// a `WritePartStatus` count and drops the datagram, re-stranding the peer).
#[test]
fn a_reask_from_a_promoted_dial_back_grant_answers_rank_with_part_status() {
    let file = hash(0x11);
    let waiter = peer_at([10, 0, 0, 2], 4000);
    let holder = peer_at([10, 0, 0, 1], 4000);
    let t = Instant::now();
    let mut state = one_waiter_state(file, 4096, waiter, 6000, 4, t);

    // Reproduce the live churn: the queued reasker drops its TCP (disconnected
    // standing), then the slot-holder drops, promoting the reasker to a
    // dial-back grant it moves out of the waiting list.
    let _ = state.on_conn_event(t, waiter, ServeConnEvent::Disconnected, &no_modifiers());
    let _ = state.on_conn_event(t, holder, ServeConnEvent::Disconnected, &no_modifiers());

    // Its FILEREASKTIME `0x90` now resolves through the dial-back grant, not
    // the (empty) waiting list, and answers rank 1 rather than dropping.
    let src = udp([10, 0, 0, 2], 6000);
    let decisions = state.on_reask_ping(t, src, &reask_ping(file));
    assert_eq!(
        decisions,
        vec![ServeDecision::SendClientUdp {
            to: src,
            datagram: ReaskAck {
                part_status: Some(PartBitmap::complete_source_sentinel()),
                rank: 1,
            }
            .encode_udp(),
            crypt_target: target_of(user(0x0A)),
        }],
    );
    // The proof a v4 counterparty can actually read it: the egress decodes
    // under the version the waiter advertised (and we advertised back).
    let ServeDecision::SendClientUdp { datagram, .. } = &decisions[0] else {
        unreachable!("asserted shape above");
    };
    let ack = ReaskAck::decode_udp(datagram, 4).expect("a v4 waiter parses the ack");
    assert_eq!(ack.rank, 1);
}

#[test]
fn purge_reaps_a_silent_waiter_but_a_reask_heartbeat_saves_it() {
    let file = hash(0x11);
    let waiter = peer_at([10, 0, 0, 2], 4000);
    let t0 = Instant::now();
    let after = Duration::from_secs(3600);
    let mut state = one_waiter_state(file, 4096, waiter, 6000, 4, t0);
    let src = udp([10, 0, 0, 2], 6000);

    // Exactly at the deadline (not strictly past) — no purge, still matched.
    assert_eq!(
        state.on_purge(t0 + after, after, &no_modifiers()),
        Vec::new()
    );
    assert!(matches!(
        state
            .on_reask_ping(t0 + after, src, &reask_ping(file))
            .as_slice(),
        [ServeDecision::SendClientUdp { .. }]
    ));

    // A reask at t0+30min refreshes the heartbeat, so a purge one hour + 1s
    // after t0 (only 30min past the last reask) keeps it.
    let mid = t0 + Duration::from_secs(1800);
    let _ = state.on_reask_ping(mid, src, &reask_ping(file));
    assert_eq!(
        state.on_purge(t0 + after + Duration::from_secs(1), after, &no_modifiers()),
        Vec::new(),
    );
    assert!(matches!(
        state.on_reask_ping(mid, src, &reask_ping(file)).as_slice(),
        [ServeDecision::SendClientUdp { .. }]
    ));

    // One hour + 1s past that last reask: purged. The now-unknown pinger's
    // reask is answered as an unknown one (queue-full at cap 8), proving the
    // standing is gone.
    let expired = mid + after + Duration::from_secs(1);
    let _ = state.on_purge(expired, after, &no_modifiers());
    assert_eq!(
        state.on_reask_ping(expired, src, &reask_ping(file)),
        vec![ServeDecision::SendClientUdp {
            to: src,
            datagram: queue_full_datagram(),
            // Never obfuscated: this branch *is* the unknown pinger (aMule:
            // "we cannot answer this one encrypted since we dont know this
            // client").
            crypt_target: None,
        }],
    );
}

#[test]
fn purge_emits_waiter_left_for_a_dropped_wait_list_entry() {
    let file = hash(0x11);
    let waiter = peer_at([10, 0, 0, 2], 4000);
    let t0 = Instant::now();
    let after = Duration::from_secs(3600);
    let mut state = one_waiter_state(file, 4096, waiter, 6000, 4, t0);

    // Silent past the purge window: the never-granted waiter is reaped, and
    // the purge sweep names it — the roster's forget path reads this event,
    // not `UploadSlotReleased`, since the waiter never held a slot.
    let expired = t0 + after + Duration::from_secs(1);
    assert_eq!(
        state.on_purge(expired, after, &no_modifiers()),
        vec![ServeDecision::Emit(ServeEvent::WaiterLeft {
            peer: waiter,
            cause: crate::WaiterLeaveCause::Purged,
        })],
    );
}

#[test]
fn purge_drops_a_waiter_whose_file_stopped_being_shared() {
    let file = hash(0x11);
    let waiter = peer_at([10, 0, 0, 2], 4000);
    let t = Instant::now();
    let mut state = one_waiter_state(file, 4096, waiter, 6000, 4, t);

    // Unshare the file, then purge: the waiter is reaped even though its
    // reask heartbeat is fresh (aMule drops queue entries for files no
    // longer shared).
    let _ = state.on_share_set(
        Vec::new(),
        std::time::Instant::now(),
        &std::collections::HashMap::new(),
    );
    let _ = state.on_purge(t, Duration::from_secs(3600), &no_modifiers());

    // With the file gone, the standing is gone: a reask now answers FNF and
    // the pinger is no longer a known waiter (a re-share would treat it as
    // an unknown pinger, not rank 1).
    let src = udp([10, 0, 0, 2], 6000);
    assert_eq!(
        state.on_reask_ping(t, src, &reask_ping(file)),
        vec![ServeDecision::SendClientUdp {
            to: src,
            datagram: file_not_found_datagram(),
            // The purge shed the waiter's identity along with its standing.
            crypt_target: None,
        }],
    );
    let _ = state.on_share_set(
        vec![entry(file, 4096, "served.bin")],
        std::time::Instant::now(),
        &std::collections::HashMap::new(),
    );
    assert_eq!(
        state.on_reask_ping(t, src, &reask_ping(file)),
        vec![ServeDecision::SendClientUdp {
            to: src,
            datagram: queue_full_datagram(),
            // Never obfuscated: this branch *is* the unknown pinger (aMule:
            // "we cannot answer this one encrypted since we dont know this
            // client").
            crypt_target: None,
        }],
        "the purged waiter is now an unknown pinger, not rank 1",
    );
}

/// An IPv6 waiter reasks over IPv6 and is answered there (ADR-0087): the
/// `0x90`/`0x91` pair is byte-identical over both families — neither body packs
/// an address — so the matrix resolves the waiter on all 128 bits and the ack
/// goes back to the v6 endpoint the ping arrived from. A neighbour in the same
/// `/64` is a different waiter, never the same one.
#[test]
fn an_ipv6_waiter_is_resolved_on_all_128_bits_and_answered_over_ipv6() {
    let file = hash(0x33);
    let two_parts = ED2K_PART_SIZE + 1;
    let waiter = v6_peer(0x0002, 4000);
    let t = Instant::now();
    let mut state = serving_state(1, vec![entry(file, two_parts, "served.bin")]);
    // The one slot goes to an unrelated peer, so both v6 peers queue behind it.
    let _ = slot_request(&mut state, peer_at([10, 0, 0, 1], 4000), file, t);
    // A neighbour in the same `/64`, queued first so it holds rank 1 — the ack
    // below must still name the reasking waiter's own rank.
    let neighbour = v6_peer(0x0003, 4000);
    identify_udp(&mut state, neighbour, user(0x0B), 6000, 4, t);
    let _ = slot_request(&mut state, neighbour, file, t);
    identify_udp(&mut state, waiter, user(0x0A), 6000, 4, t);
    let _ = slot_request(&mut state, waiter, file, t);

    let src = v6_peer(0x0002, 6000);
    assert_eq!(
        state.on_reask_ping(t, src, &reask_ping(file)),
        vec![ServeDecision::SendClientUdp {
            to: src,
            datagram: ReaskAck {
                part_status: Some(PartBitmap::complete_source_sentinel()),
                rank: 2,
            }
            .encode_udp(),
            crypt_target: target_of(user(0x0A)),
        }],
        "the v6 waiter's own rank, answered at its own v6 endpoint",
    );
}

/// aMule's client has one upload file, which its name ask, status ask, bundle
/// and slot ask each set (stock 2.3.3 `4e8f2b3c` `ClientTCPSocket.cpp:462`,
/// `:521`, `:1103`, `:606-618`) — the queued client keeping its place
/// (`UploadQueue.cpp:401-431`) — and a UDP reask is answered only for that
/// file (`ClientUDPSocket.cpp:197`, silence otherwise, `:227-229`). A waiter
/// that asks another file over TCP is therefore answered for that one, and
/// its slot, when it comes, is for the file it asked last.
#[test]
fn a_waiters_standing_follows_the_file_it_last_asked_about() {
    let (first, second) = (hash(0x31), hash(0x32));
    let waiter = peer_at([10, 0, 0, 2], 4000);
    let src = udp([10, 0, 0, 2], 6000);
    let t = Instant::now();
    let mut state = serving_state(
        1,
        vec![
            entry(first, 4096, "first.bin"),
            entry(second, 4096, "second.bin"),
        ],
    );
    let _ = slot_request(&mut state, peer_at([10, 0, 0, 1], 4000), first, t);
    identify_udp(&mut state, waiter, user(0x0A), 6000, 3, t);
    let _ = slot_request(&mut state, waiter, first, t);
    let acked =
        |state: &mut ServeState, file| !state.on_reask_ping(t, src, &reask_ping(file)).is_empty();
    assert!(acked(&mut state, first) && !acked(&mut state, second));

    // A status ask for the second file moves the standing to it.
    let _ = state.on_conn_event(
        t,
        waiter,
        ServeConnEvent::FileIdSet { file_hash: second },
        &no_modifiers(),
    );
    assert!(acked(&mut state, second) && !acked(&mut state, first));

    // A slot ask for the first moves it back, the place kept.
    assert!(matches!(
        slot_request(&mut state, waiter, first, t).as_slice(),
        [
            ServeDecision::Send {
                command: ServeConnCommand::SetQueueRank { rank: 1 },
                ..
            },
            ..
        ]
    ));
    assert!(acked(&mut state, first) && !acked(&mut state, second));
}

/// A pre-0.42 mule names its client-UDP port only in its `OP_EMULEINFO`, after
/// its hello: the waiter it already is takes the port and UDP version,
/// so its reask is answered as a UDPv4 waiter's — with our part status.
#[test]
fn an_emule_info_reask_contact_reaches_a_waiter_its_hello_named_none() {
    let file = hash(0x24);
    let waiter = peer_at([10, 0, 0, 2], 4000);
    let t = Instant::now();
    let mut state = one_waiter_state(file, 4096, waiter, 0, 0, t);
    let revised = ServeConnEvent::ReaskContactRevised {
        udp_port: 6000,
        udp_version: 4,
    };
    assert_eq!(
        state.on_conn_event(t, waiter, revised, &no_modifiers()),
        Vec::new()
    );
    let src = udp([10, 0, 0, 2], 6000);
    assert_eq!(
        state.on_reask_ping(t, src, &reask_ping(file)),
        vec![ServeDecision::SendClientUdp {
            to: src,
            datagram: ReaskAck {
                part_status: Some(PartBitmap::complete_source_sentinel()),
                rank: 1,
            }
            .encode_udp(),
            crypt_target: target_of(user(0x0A)),
        }],
    );
}
