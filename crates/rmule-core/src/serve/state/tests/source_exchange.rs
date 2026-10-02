//! Answering a peer's source-exchange ask from the engaged High-ID upload
//! clients, and the reask window that throttles a repeat ask.

use super::*;
mod claimants_and_bundles;
mod status_filtering;

/// A HighID client id from IP octets (the eD2k convention: a HighID's id is
/// its IP as a little-endian `u32`).
fn high_id_client(octets: [u8; 4]) -> ClientId {
    ClientId::from_u32(u32::from_le_bytes(octets))
}

/// Identify `p` advertising `client_id` + `listen_port` as its own source
/// coordinate (the source-exchange pool reads these, ADR-0055 §Serving).
fn identify_source(
    state: &mut ServeState,
    p: PeerEndpoint,
    user_hash: UserHash,
    client_id: ClientId,
    listen_port: u16,
    t: Instant,
) {
    identify_source_naming(state, p, user_hash, client_id, listen_port, None, t);
}

/// [`identify_source`] with the hello's `CT_MOD_IP_V6`, when it named one.
fn identify_source_naming(
    state: &mut ServeState,
    p: PeerEndpoint,
    user_hash: UserHash,
    client_id: ClientId,
    listen_port: u16,
    ipv6: Option<std::net::Ipv6Addr>,
    t: Instant,
) {
    let decisions = state.on_conn_event(
        t,
        p,
        ServeConnEvent::Identified {
            user_hash,
            client_id,
            connected_server: None,
            tcp_port: listen_port,
            udp_port: 0,
            udp_version: 0,
            extended_requests_version: 2,
            crypt: crypt_advert(),
            ipv6,
            software: nameless_software(),
        },
        &no_modifiers(),
    );
    assert_eq!(decisions, Vec::new());
}

fn sx_request(file_hash: FileHash) -> ServeConnEvent {
    ServeConnEvent::SourcesRequested {
        file_hash,
        version: ServedSourcesVersion::Sx1(rmule_peer::SourceExchangeVersion::V1),
    }
}

#[test]
fn a_source_exchange_request_answers_from_the_engaged_high_id_upload_clients() {
    use rmule_primitives::ExchangedSource;

    let file = hash(0x11);
    // Budget 3 so all three engaged peers are granted (the upload-engaged
    // pool `m_ClientUploadList` for the file).
    let mut state = serving_state(3, vec![entry(file, 4096, "served.bin")]);
    let t = Instant::now();

    // Two HighID uploaders (their advertised listen ports 4662/5000 differ
    // from the socket ports 4000, proving the serve source uses the *listen*
    // port) and one LowID uploader (dropped from the exchange).
    let high_a = peer_at([1, 2, 3, 4], 4000);
    let high_b = peer_at([5, 6, 7, 8], 4000);
    let low = peer_at([7, 7, 7, 7], 4000);
    identify_source(
        &mut state,
        high_a,
        user(0xA1),
        high_id_client([1, 2, 3, 4]),
        4662,
        t,
    );
    identify_source(
        &mut state,
        high_b,
        user(0xB2),
        high_id_client([5, 6, 7, 8]),
        5000,
        t,
    );
    identify_source(
        &mut state,
        low,
        user(0xC3),
        ClientId::from_u32(5_000),
        4662,
        t,
    );
    for p in [high_a, high_b, low] {
        let _ = slot_request(&mut state, p, file, t);
    }

    // A fourth peer (also engaged) asks us for sources — it must not be
    // served back to itself.
    let requester = peer_at([9, 9, 9, 9], 4000);
    identify_source(
        &mut state,
        requester,
        user(0xD4),
        high_id_client([9, 9, 9, 9]),
        4662,
        t,
    );
    let _ = slot_request(&mut state, requester, file, t);

    let out = state.on_conn_event(t, requester, sx_request(file), &no_modifiers());

    let expected_a = ExchangedSource::new(
        PeerSource::new(high_id_client([1, 2, 3, 4]), 4662),
        Some(user(0xA1)),
        None,
    );
    let expected_b = ExchangedSource::new(
        PeerSource::new(high_id_client([5, 6, 7, 8]), 5000),
        Some(user(0xB2)),
        None,
    );
    assert_eq!(
        out,
        vec![
            ServeDecision::Send {
                peer: requester,
                command: ServeConnCommand::AnswerSources {
                    file_hash: file,
                    sources: vec![expected_a, expected_b],
                    version: ServedSourcesVersion::Sx1(rmule_peer::SourceExchangeVersion::V1),
                },
            },
            ServeDecision::Emit(ServeEvent::SourcesServed {
                peer: requester,
                file_hash: file,
                count: 2,
            }),
        ],
        "the two engaged HighID clients are served (at their listen ports, \
         with user hashes); the LowID and the requester itself are dropped",
    );
}

#[test]
fn a_repeat_source_exchange_ask_is_throttled_within_the_reask_window() {
    let file = hash(0x22);
    let mut state = serving_state(2, vec![entry(file, 4096, "served.bin")]);
    let t = Instant::now();
    let source = peer_at([1, 2, 3, 4], 4000);
    let requester = peer_at([9, 9, 9, 9], 4000);
    identify_source(
        &mut state,
        source,
        user(0xA1),
        high_id_client([1, 2, 3, 4]),
        4662,
        t,
    );
    let _ = slot_request(&mut state, source, file, t);
    identify_source(
        &mut state,
        requester,
        user(0xD4),
        high_id_client([9, 9, 9, 9]),
        4662,
        t,
    );

    // First ask free.
    assert!(
        !state
            .on_conn_event(t, requester, sx_request(file), &no_modifiers())
            .is_empty(),
        "the first ask is answered",
    );
    // A second ask one minute later is throttled (rare file, 40-min gate).
    assert_eq!(
        state.on_conn_event(
            t + Duration::from_secs(60),
            requester,
            sx_request(file),
            &no_modifiers(),
        ),
        Vec::new(),
        "a re-ask inside the reask window sends nothing",
    );
    // 40 minutes on, the gate opens again.
    assert!(
        !state
            .on_conn_event(
                t + Duration::from_secs(40 * 60),
                requester,
                sx_request(file),
                &no_modifiers(),
            )
            .is_empty(),
        "the gate reopens at 40 minutes",
    );
}

#[test]
fn a_source_exchange_request_for_an_unshared_file_or_empty_pool_answers_nothing() {
    let file = hash(0x33);
    let mut state = serving_state(2, vec![entry(file, 4096, "served.bin")]);
    let t = Instant::now();
    let requester = peer_at([9, 9, 9, 9], 4000);
    identify_source(
        &mut state,
        requester,
        user(0xD4),
        high_id_client([9, 9, 9, 9]),
        4662,
        t,
    );

    // Shared file but no other engaged clients: the pool is empty → nothing.
    assert_eq!(
        state.on_conn_event(t, requester, sx_request(file), &no_modifiers()),
        Vec::new(),
        "a shared file with no other engaged clients sends no answer",
    );
    // A file we do not share: nothing (aMule's NULL reply).
    assert_eq!(
        state.on_conn_event(t, requester, sx_request(hash(0x99)), &no_modifiers()),
        Vec::new(),
    );
}

#[test]
fn a_low_id_client_that_named_an_ipv6_is_served_over_it_to_an_extsx_asker_only() {
    use rmule_peer::ExtSxEmission;
    use rmule_primitives::{ExchangedSource, Ipv6Endpoint};

    let file = hash(0x44);
    let mut state = serving_state(2, vec![entry(file, 4096, "served.bin")]);
    let t = Instant::now();
    // Queued with client id 0 (no server session) over IPv6, its hello naming
    // the address — the `ipv6-extsx-emit` bench's queued requester.
    let v6: std::net::Ipv6Addr = "3fff:ed2:1::7".parse().unwrap();
    let queued = PeerEndpoint::V6(Ipv6Endpoint::new(v6, 40_000));
    identify_source_naming(
        &mut state,
        queued,
        user(0x51),
        ClientId::from_u32(0),
        4662,
        Some(v6),
        t,
    );
    let _ = slot_request(&mut state, queued, file, t);

    let ext = ServedSourcesVersion::Ext {
        sx2: true,
        emission: ExtSxEmission { skip_tags: true },
    };
    let classic_asker = peer_at([8, 8, 8, 8], 4000);
    let ext_asker = peer_at([9, 9, 9, 9], 4000);
    for asker in [classic_asker, ext_asker] {
        identify_source(
            &mut state,
            asker,
            user(0xD4),
            ClientId::from_u32(0),
            4662,
            t,
        );
    }

    assert_eq!(
        state.on_conn_event(t, classic_asker, sx_request(file), &no_modifiers()),
        Vec::new(),
        "a classic entry cannot carry an IPv6-only source, and nothing else is in the pool",
    );
    let expected = ExchangedSource::new(
        PeerSource::Ipv6(Ipv6Endpoint::new(v6, 4662)),
        Some(user(0x51)),
        None,
    );
    assert_eq!(
        state.on_conn_event(
            t,
            ext_asker,
            ServeConnEvent::SourcesRequested {
                file_hash: file,
                version: ext,
            },
            &no_modifiers(),
        ),
        vec![
            ServeDecision::Send {
                peer: ext_asker,
                command: ServeConnCommand::AnswerSources {
                    file_hash: file,
                    sources: vec![expected],
                    version: ext,
                },
            },
            ServeDecision::Emit(ServeEvent::SourcesServed {
                peer: ext_asker,
                file_hash: file,
                count: 1,
            }),
        ],
        "the ExtSX asker is handed the IPv6 the hello named, at the listen port",
    );
}

/// A High-ID client whose hello named a usable IPv6 is served as one
/// dual-stack source — its IPv4 id with the IPv6 half beside it — to every
/// asker: the ExtSX writer puts `CT_MOD_IP_V6` beside the id, the classic one
/// writes the id alone (both pinned at the session's wire).
#[test]
fn a_high_id_client_that_named_an_ipv6_is_served_with_both_addresses() {
    use rmule_peer::ExtSxEmission;
    use rmule_primitives::{ExchangedSource, Ipv6Endpoint};

    let file = hash(0x45);
    let mut state = serving_state(2, vec![entry(file, 4096, "served.bin")]);
    let t = Instant::now();
    let v6: std::net::Ipv6Addr = "3fff:ed2:1::7".parse().unwrap();
    let queued = peer_at([198, 51, 100, 7], 40_000);
    let id = high_id_client([198, 51, 100, 7]);
    identify_source_naming(&mut state, queued, user(0x51), id, 4662, Some(v6), t);
    let _ = slot_request(&mut state, queued, file, t);

    let asker = peer_at([9, 9, 9, 9], 4000);
    identify_source(
        &mut state,
        asker,
        user(0xD4),
        ClientId::from_u32(0),
        4662,
        t,
    );
    let ext = ServedSourcesVersion::Ext {
        sx2: true,
        emission: ExtSxEmission { skip_tags: true },
    };
    let decisions = state.on_conn_event(
        t,
        asker,
        ServeConnEvent::SourcesRequested {
            file_hash: file,
            version: ext,
        },
        &no_modifiers(),
    );
    let expected = ExchangedSource::new(PeerSource::new(id, 4662), Some(user(0x51)), None)
        .with_ipv6_half(Some(Ipv6Endpoint::new(v6, 4662)));
    assert_eq!(
        decisions.first(),
        Some(&ServeDecision::Send {
            peer: asker,
            command: ServeConnCommand::AnswerSources {
                file_hash: file,
                sources: vec![expected],
                version: ext,
            },
        }),
    );
}

/// The name ask that tells the serve state which parts `p` holds of `file`
/// (the `0x58` status, ADR-0055 §Serving).
fn name_ask(
    state: &mut ServeState,
    p: PeerEndpoint,
    file: FileHash,
    part_status: Option<PartBitmap>,
    t: Instant,
) {
    let _ = state.on_conn_event(
        t,
        p,
        ServeConnEvent::FileRequested {
            file_hash: file,
            status: part_status
                .as_ref()
                .map(PartStatusTail::of)
                .unwrap_or_default(),
        },
        &no_modifiers(),
    );
}

/// A file served to four engaged HighID sources: `a` asked holding part 0,
/// `b` holding part 1, `c` never said (unknown status), `d` holding nothing.
/// Returns the state and the four sources in pool order.
fn pool_with_known_unknown_and_empty_status(
    file: FileHash,
    size: u64,
    t: Instant,
) -> (ServeState, [rmule_primitives::ExchangedSource; 4]) {
    use rmule_primitives::ExchangedSource;

    let mut state = serving_state(4, vec![entry(file, size, "served.bin")]);
    let pool: [(_, _, Option<&[u32]>); 4] = [
        ([1, 2, 3, 4], 0xA1, Some(&[0])),
        ([5, 6, 7, 8], 0xB2, Some(&[1])),
        ([6, 6, 6, 6], 0xC3, None),
        ([4, 4, 4, 4], 0xE5, Some(&[])),
    ];
    let sources = pool.map(|(octets, hash_byte, held)| {
        let p = peer_at(octets, 4000);
        identify_source(
            &mut state,
            p,
            user(hash_byte),
            high_id_client(octets),
            4662,
            t,
        );
        if let Some(parts) = held {
            let status = PartBitmap::downloader(size, |i| parts.contains(&i.value()));
            name_ask(&mut state, p, file, Some(status), t);
        }
        let _ = slot_request(&mut state, p, file, t);
        ExchangedSource::new(
            PeerSource::new(high_id_client(octets), 4662),
            Some(user(hash_byte)),
            None,
        )
    });
    (state, sources)
}

fn answered(
    state: &mut ServeState,
    asker: PeerEndpoint,
    file: FileHash,
    version: ServedSourcesVersion,
    t: Instant,
) -> Vec<rmule_primitives::ExchangedSource> {
    let out = state.on_conn_event(
        t,
        asker,
        ServeConnEvent::SourcesRequested {
            file_hash: file,
            version,
        },
        &no_modifiers(),
    );
    match out.first() {
        Some(ServeDecision::Send {
            command: ServeConnCommand::AnswerSources { sources, .. },
            ..
        }) => sources.clone(),
        other => panic!("expected a source answer, got {other:?}"),
    }
}
