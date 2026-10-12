//! Name-ask status handling by the asker's claimed extension level, the part-count
//! read, and bundled name-status requests.

use super::*;

/// Identify `p` (a HighID at `octets`) with its hello's extended-requests
/// claim and UDP contact spelled out.
fn identify_claiming(
    state: &mut ServeState,
    octets: [u8; 4],
    extended_requests_version: u8,
    udp_version: u8,
    t: Instant,
) -> PeerEndpoint {
    let p = peer_at(octets, 4000);
    let _ = state.on_conn_event(
        t,
        p,
        HelloFacts {
            client_id: high_id_client(octets),
            udp_port: 6000,
            udp_version,
            extended_requests_version,
            ..HelloFacts::of(user(octets[0]))
        }
        .identified(),
        &no_modifiers(),
    );
    p
}

/// A status from a peer whose hello claimed extended requests
/// `0` is discarded — aMule clears it and returns before reading (stock
/// 2.3.3 `4e8f2b3c` `UploadClient.cpp:400-406`) — so that asker gets the
/// answer for an asker without a status, while a v1 claimant's same status
/// filters its answer.
#[test]
fn a_v0_claimants_name_ask_status_is_discarded_and_a_v1_claimants_kept() {
    let file = hash(0x58);
    let size = 2 * ED2K_PART_SIZE + 1_000;
    let t = Instant::now();
    let (mut state, [a, b, c, _d]) = pool_with_known_unknown_and_empty_status(file, size, t);

    // Both hold parts 0 and 1 and lack part 2, which no pooled source offers.
    let holds_0_and_1 = PartBitmap::downloader(size, |i| i.value() < 2);
    for (octets, claim, expected) in [([8, 8, 8, 8], 1, vec![c]), ([9, 9, 9, 9], 0, vec![a, b, c])]
    {
        let asker = identify_claiming(&mut state, octets, claim, 0, t);
        name_ask(&mut state, asker, file, Some(holds_0_and_1.clone()), t);
        assert_eq!(
            answered(&mut state, asker, file, t,),
            expected,
            "extended-requests claim {claim}",
        );
    }
}

/// The reask path: a UDPv4 waiter that claimed extended requests
/// `0` is still answered, but the status its ping restates is discarded as
/// its name ask's was — aMule hands both to the same reader
/// (`ClientUDPSocket.cpp:202-203`, `UploadClient.cpp:403-406`).
#[test]
fn a_v0_claimants_udp_reask_status_is_discarded_too() {
    let file = hash(0x59);
    let size = 2 * ED2K_PART_SIZE + 1_000;
    let t = Instant::now();
    let (mut state, [a, b, c, _d]) = pool_with_known_unknown_and_empty_status(file, size, t);

    // Queued behind the four granted sources.
    let waiter = identify_claiming(&mut state, [10, 0, 0, 2], 0, 4, t);
    let _ = slot_request(&mut state, waiter, file, t);
    let ping = ReaskFilePing {
        file_hash: file,
        part_status: Some(PartBitmap::downloader(size, |i| i.value() < 2)),
        complete_sources: Some(0),
    }
    .encode_udp();
    assert!(matches!(
        state
            .on_reask_ping(t, udp([10, 0, 0, 2], 6000), &ping)
            .as_slice(),
        [ServeDecision::SendClientUdp { .. }],
    ));
    assert_eq!(answered(&mut state, waiter, file, t,), vec![a, b, c],);
}

/// A name ask that is the hash alone, from a peer whose hello
/// claimed extended requests, makes aMule's reader throw (stock 2.3.3
/// `4e8f2b3c` `UploadClient.cpp:408-412`) and its packet handler disconnect
/// the client (`ClientTCPSocket.cpp:2018-2047`): nothing is answered and the
/// connection ends, named. A `0` claimant's bare ask is its own shape.
#[test]
fn a_hash_only_name_ask_ends_the_connection_only_from_a_peer_claiming_extended_requests() {
    let file = hash(0x5A);
    let t = Instant::now();
    let mut state = serving_state(1, vec![entry(file, 4096, "served.bin")]);
    let bare = ServeInput::Server(ServerEvent::FileRequested {
        file_hash: file,
        status: PartStatusTail::default(),
    });

    let claimant = identify_claiming(&mut state, [8, 8, 8, 8], 1, 0, t);
    assert_eq!(
        state.on_conn_event(t, claimant, bare.clone(), &no_modifiers()),
        vec![
            ServeDecision::Emit(ServeEvent::NameAskMalformed { peer: claimant }),
            ServeDecision::Disconnect { peer: claimant },
        ],
    );

    let v0 = identify_claiming(&mut state, [9, 9, 9, 9], 0, 0, t);
    assert_eq!(
        state.on_conn_event(t, v0, bare, &no_modifiers()),
        vec![ServeDecision::Send {
            peer: v0,
            command: ServerCommand::AnswerFileName {
                file_hash: file,
                file_name: rmule_primitives::Ed2kText::from_utf8("served.bin"),
            },
        }],
    );
}

/// A standalone name ask's status is read by the asked file, not
/// by the count on the wire (stock 2.3.3 `4e8f2b3c` `UploadClient.cpp:414-446`,
/// the reader a UDPv4 reask shares): the bitmap spans the file's real parts,
/// one short of the wire's count for an exact multiple of the part size; a
/// count that is not the file's clears the status and the ask is still
/// answered (`:418-422`); a bitmap short of the file's parts throws, and the
/// connection ends.
#[test]
fn a_name_asks_status_is_read_by_the_files_part_count_not_the_wires() {
    let file = hash(0x5B);
    let size = 8 * ED2K_PART_SIZE; // eight real parts, a wire count of nine
    let t = Instant::now();
    let mut state = serving_state(1, vec![entry(file, size, "served.bin")]);
    let asker = identify_claiming(&mut state, [8, 8, 8, 8], 1, 0, t);
    let ask = |tail: &[u8]| {
        let wire = [file.as_bytes().as_slice(), tail].concat();
        let packet =
            rmule_primitives::Packet::new(rmule_primitives::PacketProtocol::Edonkey, 0x58, wire);
        ServeInput::Server(ServerEvent::FileRequested {
            file_hash: file,
            status: rmule_peer::RequestFileName::decode_packet(&packet)
                .unwrap()
                .status,
        })
    };
    let answered = vec![ServeDecision::Send {
        peer: asker,
        command: ServerCommand::AnswerFileName {
            file_hash: file,
            file_name: rmule_primitives::Ed2kText::from_utf8("served.bin"),
        },
    }];

    // The file's count, one byte covering its eight real parts.
    assert_eq!(
        state.on_conn_event(t, asker, ask(&[0x09, 0x00, 0x0F]), &no_modifiers()),
        answered
    );
    assert!(state.sx_part_status.contains_key(&(asker, file)));

    // Another count, no bitmap to speak of: cleared, still answered.
    assert_eq!(
        state.on_conn_event(t, asker, ask(&[0x03, 0x00]), &no_modifiers()),
        answered
    );
    assert!(!state.sx_part_status.contains_key(&(asker, file)));

    // The file's count with no bitmap at all: the reader throws.
    assert_eq!(
        state.on_conn_event(t, asker, ask(&[0x09, 0x00]), &no_modifiers()),
        vec![
            ServeDecision::Emit(ServeEvent::NameAskMalformed { peer: asker }),
            ServeDecision::Disconnect { peer: asker },
        ],
    );
}

/// The bundle's asks as the session hands them on, from a real request packet
/// decoded at level 1 (name and status asks only).
fn bundle_event(packet: &rmule_primitives::Packet) -> ServeInput {
    let req = rmule_peer::MultiPacketRequest::decode_packet(
        packet,
        rmule_peer::ExtendedRequests::negotiated(1, 2),
    )
    .unwrap();
    ServeInput::Server(ServerEvent::FileBundleRequested {
        file_hash: req.file_hash,
        file_size: req.file_size,
        asks: req
            .items
            .into_iter()
            .map(|item| match item {
                rmule_peer::RequestItem::Name { part_status } => BundledAsk::Name { part_status },
                rmule_peer::RequestItem::SetReqId => BundledAsk::SetReqId,
                other => panic!("not used here: {other:?}"),
            })
            .collect(),
        cut: req.cut,
    })
}

/// Both bundle shapes: a name sub whose count is not the file's clears
/// the asker's status and the bundle is still answered in full, as aMule's
/// `ProcessExtendedInfo` clears and returns (stock 2.3.3 `4e8f2b3c`
/// `UploadClient.cpp:418-422`). `OP_MULTIPACKET_EXT` is read by the size it
/// carries (the walk takes only the count's two bytes); a plain
/// `OP_MULTIPACKET` carries no size, so its status is walked by the wire's
/// count and dropped here against the file (ADR-0055 §Name-ask surface).
#[test]
fn a_bundled_name_status_whose_count_is_not_the_files_is_cleared_and_the_bundle_answered() {
    let file = hash(0x5C);
    let t = Instant::now();
    let mut state = serving_state(1, vec![entry(file, 4096, "served.bin")]);
    let asker = identify_claiming(&mut state, [8, 8, 8, 8], 1, 0, t);
    let packet = |opcode: u8, size: Option<u64>, subs: &[u8]| {
        let mut payload = file.as_bytes().to_vec();
        if let Some(size) = size {
            payload.extend_from_slice(&size.to_le_bytes());
        }
        payload.extend_from_slice(subs);
        rmule_primitives::Packet::new(rmule_primitives::PacketProtocol::Emule, opcode, payload)
    };
    let answered = |decisions: &[ServeDecision]| {
        matches!(
            decisions,
            [
                ServeDecision::Send {
                    command: ServerCommand::AnswerFileName { .. },
                    ..
                },
                ServeDecision::Send {
                    command: ServerCommand::AnswerFileStatus { .. },
                    ..
                },
            ]
        )
    };
    let shapes = [
        packet(0xA4, Some(4096), &[0x58, 0x20, 0x00, 0x4F]),
        packet(0x92, None, &[0x58, 0x20, 0x00, 0, 0, 0, 0, 0x4F]),
    ];
    for shape in &shapes {
        // A status the file can read stands first, so clearing is visible.
        let good = packet(0x92, None, &[0x58, 0x01, 0x00, 0x01]);
        let _ = state.on_conn_event(t, asker, bundle_event(&good), &no_modifiers());
        assert!(state.sx_part_status.contains_key(&(asker, file)));

        let decisions = state.on_conn_event(t, asker, bundle_event(shape), &no_modifiers());
        assert!(answered(&decisions), "{decisions:?}");
        assert!(!state.sx_part_status.contains_key(&(asker, file)));
    }
}

/// A bundle cut short inside a sub-ask is gated first, as aMule walks nothing
/// before its file gate (`ClientTCPSocket.cpp:1061-1085`): for a file we do
/// not share it draws the one not-found, and for a shared file the walk's
/// throw ends the connection (`:2018-2047`) with nothing answered, counted.
#[test]
fn a_bundle_cut_short_is_gated_before_it_ends_the_connection() {
    let file = hash(0x5D);
    let t = Instant::now();
    let mut state = serving_state(1, vec![entry(file, 4096, "served.bin")]);
    let asker = identify_claiming(&mut state, [8, 8, 8, 8], 1, 0, t);
    let cut = |file_hash| {
        ServeInput::Server(ServerEvent::FileBundleRequested {
            file_hash,
            file_size: None,
            asks: vec![BundledAsk::SetReqId],
            cut: Some(rmule_peer::BundleCut::NameStatus(None)),
        })
    };
    assert_eq!(
        state.on_conn_event(t, asker, cut(hash(0x99)), &no_modifiers()),
        vec![ServeDecision::Send {
            peer: asker,
            command: ServerCommand::AnswerFileNotFound {
                file_hash: hash(0x99)
            },
        }],
    );
    assert_eq!(
        state.on_conn_event(t, asker, cut(file), &no_modifiers()),
        vec![
            ServeDecision::Emit(ServeEvent::NameAskMalformed { peer: asker }),
            ServeDecision::Disconnect { peer: asker },
        ],
    );
}
