//! Discovered sources joining the candidate pool: server-UDP global sources
//! (ADR-0051) dialing High-ID and holding a per-server callback for Low-ID,
//! and Kad sources (ADR-0043), which carry no callback route at all.

use super::*;

#[test]
fn on_global_sources_dials_high_id_and_holds_low_id_for_a_per_server_callback() {
    use rmule_primitives::{ClientId, PeerSource};
    // Callback-capable, empty pools, room for two workers.
    let server = source_server(9);
    let mut state = callback_state(Vec::new(), Vec::new(), true, 2);
    let high = PeerSource::new(ClientId::from_u32(u32::from_le_bytes([10, 0, 0, 5])), 4662);
    let low_src = PeerSource::new(low(7), 4662);

    let decisions = state.on_global_sources(server, vec![high, low_src]);

    // The High-ID global source is pooled and dialed.
    assert!(
        decisions
            .iter()
            .any(|d| matches!(d, Decision::Spawn { peer: p, .. } if *p == peer(5))),
        "High-ID global source must be dialed: {decisions:?}"
    );
    // ADR-0051: the Low-ID global source is usable — held as a callback candidate
    // tagged with *its own* source-server, requesting a per-server callback
    // (not the connected-server `RequestCallback`, which would mis-route).
    assert!(
        decisions.iter().any(|d| matches!(d,
            Decision::RequestGlobalCallback { low_id, source_server }
                if *low_id == low(7) && *source_server == server)),
        "Low-ID global source must request a per-server callback: {decisions:?}"
    );
    // Paired with an ArmCallbackTimeout keyed by the source-server (the global form).
    assert!(
        decisions.iter().any(|d| matches!(d,
            Decision::ArmCallbackTimeout { key, .. }
                if *key == CallbackKey { server: Some(server), low_id: low(7) })),
        "RequestGlobalCallback is paired with ArmCallbackTimeout for the same key: {decisions:?}"
    );
    assert!(
        !decisions
            .iter()
            .any(|d| matches!(d, Decision::RequestCallback { .. })),
        "a global Low-ID source must not use the connected-server callback"
    );
}

#[test]
fn on_kad_sources_dials_direct_high_id_sources() {
    use rmule_primitives::{ClientId, PeerSource};
    let mut state = callback_state(Vec::new(), Vec::new(), true, 2);
    let direct = PeerSource::new(ClientId::from_u32(u32::from_le_bytes([10, 0, 0, 5])), 4662);

    let decisions = state.on_kad_sources(vec![crate::KadSource::dialable(direct)]);

    assert!(
        decisions
            .iter()
            .any(|d| matches!(d, Decision::Spawn { peer: p, .. } if *p == peer(5))),
        "a direct Kad source must be pooled and dialed: {decisions:?}"
    );
}

/// A direct Kad row's `TAG_ENCRYPTION` byte and hash reach its dial:
/// a row that requires obfuscation is met by the outbound rule, so a
/// node with obfuscation off never dials it at all.
#[test]
fn a_direct_kad_rows_crypt_side_reaches_its_dial() {
    use rmule_primitives::{
        ClientId, CryptStance, OutboundCrypt, PeerSource, SourceCryptOptions, UserHash,
    };
    let mut state = callback_state(Vec::new(), Vec::new(), true, 2);
    let direct = PeerSource::new(ClientId::from_u32(u32::from_le_bytes([10, 0, 0, 5])), 4662);
    let row = crate::KadSource {
        user_hash: Some(UserHash::from_bytes([0x5A; 16])),
        connect_options: Some(SourceCryptOptions::from_byte(0x07)),
        ..crate::KadSource::dialable(direct)
    };

    let _ = state.on_kad_sources(vec![row]);

    assert_eq!(
        state.peer_crypt(peer(5)).outbound(CryptStance::disabled()),
        OutboundCrypt::Incompatible
    );
}

/// The peer's own hello outranks its record while its worker lives
/// (ADR-0049) — but the hello rides that worker, not the
/// endpoint forever (ADR-0049, ADR-0090 "Attachments"):
/// once the worker retires, `hello_crypts` is pruned with it, so a
/// source whose Kad row said "supports" and whose hello said "requires" is
/// met on the bare record again the next time it is sighted, until a fresh
/// hello restates a stance.
#[test]
fn a_retired_hellos_required_crypt_does_not_outlive_its_worker() {
    use rmule_primitives::{
        ClientId, CryptStance, OutboundCrypt, PeerSource, SourceCryptOptions, UserHash,
    };
    let ours = CryptStance::new(true, false, false);
    let hello_hash = UserHash::from_bytes([0x6B; 16]);
    let mut state = callback_state(Vec::new(), Vec::new(), true, 2);
    let direct = PeerSource::new(ClientId::from_u32(u32::from_le_bytes([10, 0, 0, 5])), 4662);
    let supports_only_row = || crate::KadSource {
        user_hash: Some(UserHash::from_bytes([0x5A; 16])),
        connect_options: Some(SourceCryptOptions::from_byte(0x01)),
        ..crate::KadSource::dialable(direct)
    };

    let _ = state.on_kad_sources(vec![supports_only_row()]);
    assert_eq!(
        state.peer_crypt(peer(5)).outbound(ours),
        OutboundCrypt::Plaintext,
        "the record alone: support met by support dials clear"
    );
    let _ = state.on_worker_event(
        peer(5),
        PeerWorkerEvent::Identified {
            user_hash: hello_hash,
            crypt: Some(CryptStance::new(true, true, true)),
            software: hello_software(),
        },
    );
    let _ = state.on_worker_event(peer(5), PeerWorkerEvent::Disconnected);
    let _ = state.on_kad_sources(vec![supports_only_row()]);

    assert_eq!(
        state.peer_crypt(peer(5)).outbound(ours),
        OutboundCrypt::Plaintext,
        "the retired worker's hello is gone; the freshly-sighted record governs again"
    );
}

/// The other direction (superseded at the worker's retirement): a
/// hello that advertised no crypt outranks a record that asked for it while
/// the hello's worker lives, but does not survive that worker's retirement
/// — the record it never itself un-asked for is what the next dial meets.
#[test]
fn a_retired_hellos_disabled_crypt_does_not_outlive_its_worker() {
    use rmule_primitives::{
        ClientId, CryptStance, OutboundCrypt, PeerSource, SourceCryptOptions, UserHash,
    };
    let ours = CryptStance::new(true, false, false);
    let hash = UserHash::from_bytes([0x5A; 16]);
    let mut state = callback_state(Vec::new(), Vec::new(), true, 2);
    let direct = PeerSource::new(ClientId::from_u32(u32::from_le_bytes([10, 0, 0, 5])), 4662);
    let requesting_row = crate::KadSource {
        user_hash: Some(hash),
        connect_options: Some(SourceCryptOptions::from_byte(0x03)),
        ..crate::KadSource::dialable(direct)
    };

    let _ = state.on_kad_sources(vec![requesting_row]);
    assert_eq!(
        state.peer_crypt(peer(5)).outbound(ours),
        OutboundCrypt::Obfuscated { toward: hash },
        "the record alone asks, so the first dial is obfuscated"
    );
    let _ = state.on_worker_event(
        peer(5),
        PeerWorkerEvent::Identified {
            user_hash: hash,
            crypt: Some(CryptStance::disabled()),
            software: hello_software(),
        },
    );
    let _ = state.on_worker_event(peer(5), PeerWorkerEvent::Disconnected);

    assert_eq!(
        state.peer_crypt(peer(5)).outbound(ours),
        OutboundCrypt::Obfuscated { toward: hash },
        "the retired worker's silent hello is gone; the standing record still asks"
    );
}

/// The adoption case of the hello's crypt stance: a called-back Low-ID peer carries
/// no *record* at all — only a Kad row or a High-ID server-lookup ever
/// populates `peer_crypts`, and a connected-server callback candidate is
/// neither — so before its own hello arrives, `peer_crypt` reads
/// `PeerCrypt::unknown` and every dial is plaintext. Once
/// `on_callback_connected` adopts it and its `Identified` event carries the
/// accept-side identity's stance (as the fixed adoption path now does), the
/// adopted peer is dialed per its hello exactly as a directly-dialed one is.
#[test]
fn an_adopted_callback_peer_is_dialed_per_its_hello_stance() {
    use rmule_primitives::{CryptStance, OutboundCrypt, UserHash};
    let ours = CryptStance::new(true, false, false);
    let hello_hash = UserHash::from_bytes([0x6B; 16]);
    let mut state = callback_state(Vec::new(), vec![low_candidate(7)], true, 2);

    let _ = state.start();
    assert_eq!(
        state.peer_crypt(peer(9)).outbound(ours),
        OutboundCrypt::Plaintext,
        "a callback candidate carries no record, so nothing has stated a stance yet"
    );

    let _ = state.on_callback_connected(connected_key(low(7)), peer(9));
    let _ = state.on_worker_event(
        peer(9),
        PeerWorkerEvent::Identified {
            user_hash: hello_hash,
            crypt: Some(CryptStance::new(true, true, true)),
            software: hello_software(),
        },
    );

    assert_eq!(
        state.peer_crypt(peer(9)).outbound(ours),
        OutboundCrypt::Obfuscated { toward: hello_hash },
        "the adopted worker's own identity seeds hello_crypts, same as a dialed worker's hello"
    );
}

#[test]
fn on_kad_sources_drops_a_low_id_row_entirely() {
    use rmule_primitives::PeerSource;
    // Even callback-capable: a bare Low-ID Kad row names no buddy, and Kad has
    // no source-server to relay a callback through (ADR-0043).
    let mut state = callback_state(Vec::new(), Vec::new(), true, 2);

    let decisions = state.on_kad_sources(vec![crate::KadSource::dialable(PeerSource::new(
        low(7),
        4662,
    ))]);

    assert!(
        decisions.is_empty(),
        "a non-dialable Kad row is dropped, never callback-held: {decisions:?}"
    );
}

/// The headline case: a type-3/5 row that names a buddy is a
/// candidate, and its road is the buddy's — never a server callback, because a
/// Kad row is in no server's namespace. A downloader that cannot be dialed
/// back punches it at once (a capable one asks the buddy for a callback
/// first, `tests::buddy_callback`).
#[test]
fn a_kad_buddy_row_becomes_a_punchable_candidate_and_never_a_server_callback() {
    let mut state = callback_state(Vec::new(), Vec::new(), false, 2);

    // eMuleAI's connect-options byte: bit 7 is CONNECT_OPT_NAT_TRAVERSAL_UTP.
    let decisions = state.on_kad_sources(vec![kad_buddy_row(0x81)]);

    assert!(
        !decisions.iter().any(|d| matches!(
            d,
            Decision::RequestCallback { .. } | Decision::RequestGlobalCallback { .. }
        )),
        "no server can be asked to relay for a Kad row: {decisions:?}"
    );
    assert!(
        decisions
            .iter()
            .any(|d| matches!(d, Decision::FallToNatTraversal { .. })),
        "a buddy-bearing Kad row takes the punch road: {decisions:?}"
    );
}

/// An aMule or eMule publisher sets no NAT-T bit in its Kad `TAG_ENCRYPTION`
/// (only eMuleAI routes that byte through the global `GetMyConnectOptions`),
/// so a downloader that cannot be dialed back pools its buddy row honestly
/// unusable rather than punching a peer that would not answer. The bit is
/// read, never invented.
#[test]
fn a_kad_buddy_row_without_the_natt_bit_opens_no_road_for_a_low_id_downloader() {
    let mut state = callback_state(Vec::new(), Vec::new(), false, 2);

    // aMule's byte: crypt supported/requested, no 0x80.
    let decisions = state.on_kad_sources(vec![kad_buddy_row(0x03)]);

    assert!(
        !decisions.iter().any(|d| matches!(
            d,
            Decision::RequestCallback { .. }
                | Decision::RequestGlobalCallback { .. }
                | Decision::RequestBuddyCallback { .. }
                | Decision::FallToNatTraversal { .. }
        )),
        "a buddy row from a publisher that never claimed NAT-T opens no road: {decisions:?}"
    );
}

/// One decoded type-3 row: a firewalled publisher behind a buddy, with
/// `connect_options` left to the caller.
pub(super) fn kad_buddy_row(connect_options: u8) -> crate::KadSource {
    use rmule_primitives::{Ipv4Endpoint, SourceCryptOptions, UserHash};
    crate::KadSource {
        direct: None,
        user_hash: Some(UserHash::from_bytes([0xAB; UserHash::BYTE_LEN])),
        kad_udp: Some(Ipv4Endpoint::new(
            std::net::Ipv4Addr::new(198, 51, 100, 77),
            4672,
        )),
        connect_options: Some(SourceCryptOptions::from_byte(connect_options)),
        buddy: Some(rmule_kad::KadBuddyContact {
            buddy_id: rmule_kad::KadId::from_bytes([0x7A; rmule_kad::KadId::BYTE_LEN]),
            buddy_udp: Some(Ipv4Endpoint::new(
                std::net::Ipv4Addr::new(45, 55, 200, 9),
                9000,
            )),
            buddy_ipv6: None,
            buddy_udp_ipv6: None,
        }),
        direct_udp_callback: false,
        tcp_port: 4662,
        ipv6: None,
    }
}

/// A bare Low-ID global source is the one shape neither road of the admission
/// rule reaches (ADR-0091): we cannot be called back for it, and
/// its own server is not ours to ask for an introduction.
#[test]
fn on_global_sources_opens_no_road_for_a_bare_low_id_global_without_callback_capability() {
    use rmule_primitives::PeerSource;
    let server = source_server(9);
    let mut state = callback_state(Vec::new(), Vec::new(), false, 2);

    let decisions = state.on_global_sources(server, vec![PeerSource::new(low(7), 4662)]);

    assert!(
        !decisions.iter().any(|d| matches!(
            d,
            Decision::RequestGlobalCallback { .. }
                | Decision::RequestCallback { .. }
                | Decision::FallToNatTraversal { .. }
        )),
        "a Low-ID global source stays unusable when rmule cannot be called back: {decisions:?}"
    );
}

/// A **Sentinel Source** from a capable server is a dialable candidate, not a
/// held callback: it carries an address of its own, so the Low-ID branch never
/// sees it and no callback is requested for a peer that needs none (ADR-0087
/// §4.4).
#[test]
fn a_sentinel_ipv6_source_is_pooled_and_dialed_rather_than_called_back() {
    use rmule_primitives::{Ipv6Endpoint, PeerSource};
    let endpoint = Ipv6Endpoint::new("2a01:4f8::7".parse().unwrap(), 4662);
    let mut state = callback_state(Vec::new(), Vec::new(), true, 2);

    let decisions = state.on_global_sources(source_server(9), vec![PeerSource::Ipv6(endpoint)]);

    assert!(
        decisions.iter().any(|d| matches!(
            d,
            Decision::Spawn { peer: PeerEndpoint::V6(p), .. } if *p == endpoint
        )),
        "the IPv6 source must be dialed in its own family: {decisions:?}"
    );
    assert!(
        !decisions.iter().any(|d| matches!(
            d,
            Decision::RequestCallback { .. } | Decision::RequestGlobalCallback { .. }
        )),
        "an IPv6 source needs no broker: {decisions:?}"
    );
}

/// Fixtures for the crypt-stance precedence pairs (ADR-0049):
/// peer 5 as a Kad row and as a source-exchange entry.
mod crypt_stance {
    use super::*;
    use rmule_primitives::{
        ClientId, CryptStance, ExchangedSource, OutboundCrypt, PeerSource, SourceCryptOptions,
        UserHash,
    };

    const HASH: UserHash = UserHash::from_bytes([0x5A; 16]);
    const SUPPORTS: CryptStance = CryptStance::new(true, false, false);

    fn kad_row(hash: UserHash, options: Option<u8>) -> crate::KadSource {
        let direct = PeerSource::new(ClientId::from_u32(u32::from_le_bytes([10, 0, 0, 5])), 4662);
        crate::KadSource {
            user_hash: Some(hash),
            connect_options: options.map(SourceCryptOptions::from_byte),
            ..crate::KadSource::dialable(direct)
        }
    }

    fn exchanged(state: &mut DownloadState, hash: UserHash, options: Option<u8>) {
        let PeerEndpoint::V4(v4) = peer(5) else {
            unreachable!()
        };
        let source = ExchangedSource::new(
            PeerSource::HighId(v4),
            Some(hash),
            options.map(SourceCryptOptions::from_byte),
        );
        let _ = state.on_worker_event(
            peer(1),
            PeerWorkerEvent::SourcesReceived {
                sources: vec![source],
            },
        );
    }

    /// Hello vs Kad row: a Kad row arriving *after* the hello — even one
    /// stating "no crypt" — never displaces what the peer said itself.
    #[test]
    fn a_later_kad_row_never_outranks_the_peers_own_hello() {
        let mut state = callback_state(Vec::new(), Vec::new(), true, 2);
        let _ = state.on_worker_event(
            peer(5),
            PeerWorkerEvent::Identified {
                user_hash: HASH,
                crypt: Some(CryptStance::new(true, true, true)),
                software: hello_software(),
            },
        );
        let _ = state.on_worker_event(peer(5), PeerWorkerEvent::Disconnected);
        let _ = state.on_kad_sources(vec![kad_row(HASH, Some(0x00))]);

        assert_eq!(
            state.peer_crypt(peer(5)).outbound(SUPPORTS),
            OutboundCrypt::Obfuscated { toward: HASH }
        );
    }

    /// Kad row vs ExtSX: two third-party statements — the newer one wins,
    /// whichever channel it came by.
    #[test]
    fn a_newer_exchanged_stance_replaces_an_older_kad_rows() {
        let mut state = callback_state(Vec::new(), Vec::new(), true, 2);
        let _ = state.on_kad_sources(vec![kad_row(HASH, Some(0x07))]);
        exchanged(&mut state, HASH, Some(0x01));

        assert_eq!(
            state.peer_crypt(peer(5)).outbound(CryptStance::disabled()),
            OutboundCrypt::Plaintext,
            "the newer supports-only statement, not the older requires"
        );
    }

    /// Newest vs older third party, another owner: a newer record naming a
    /// different User Hash replaces the older record whole — the older peer's
    /// "requires" never rides onto the new one.
    #[test]
    fn a_newer_record_naming_another_hash_carries_no_older_stance() {
        let other = UserHash::from_bytes([0x6B; 16]);
        let mut state = callback_state(Vec::new(), Vec::new(), true, 2);
        exchanged(&mut state, HASH, Some(0x07));
        let _ = state.on_kad_sources(vec![kad_row(other, None)]);

        assert_eq!(
            state.peer_crypt(peer(5)).outbound(CryptStance::disabled()),
            OutboundCrypt::Plaintext
        );
        assert_eq!(state.peer_crypt(peer(5)).user_hash(), Some(other));
    }

    /// No invented stance: a record that carried no crypt byte (an SX v2
    /// entry — hash, no options) is silence, not "no crypt"; the stance a
    /// Kad row stated stands, so a node with obfuscation off still refuses
    /// the peer that requires it.
    #[test]
    fn a_record_with_no_crypt_byte_invents_no_stance_over_a_stated_one() {
        let mut state = callback_state(Vec::new(), Vec::new(), true, 2);
        let _ = state.on_kad_sources(vec![kad_row(HASH, Some(0x07))]);
        exchanged(&mut state, HASH, None);

        assert_eq!(
            state.peer_crypt(peer(5)).outbound(CryptStance::disabled()),
            OutboundCrypt::Incompatible
        );
    }
}

/// The known-source count the Transfers table shows: a source moving
/// from a pool into a worker slot is still known, and one that failed and was
/// retired is not.
#[test]
fn known_sources_count_the_slots_and_the_pools_and_drop_a_retired_source() {
    let mut state = callback_state(
        vec![peer(1), peer(2), peer(3)],
        vec![low_candidate(7)],
        true,
        1,
    );
    assert_eq!(state.known_sources(), 4);
    let started = state.start();
    assert_eq!(spawned(&started), [peer(1)]);
    assert_eq!(
        state.known_sources(),
        4,
        "a dial moves a source, it does not add one"
    );

    let backfill = state.on_worker_event(peer(1), PeerWorkerEvent::Disconnected);
    assert_eq!(spawned(&backfill), [peer(2)]);
    assert_eq!(state.known_sources(), 3, "the failed source left");
}

/// A source that queued us and hung up is still known: the reask
/// heartbeat holds it for its slot, so Src counts it — once, while its worker
/// is still ending and after.
#[test]
fn known_sources_count_a_source_that_queued_us_once() {
    let mut state = callback_state(vec![peer(1)], Vec::new(), true, 1);
    let _ = state.start();
    let _ = state.on_worker_event(peer(1), PeerWorkerEvent::Connected);
    state.enter_remote_queue(peer(1));
    assert_eq!(state.known_sources(), 1, "held by its worker and the queue");

    let _ = state.on_worker_event(peer(1), PeerWorkerEvent::Disconnected);
    assert_eq!(state.known_sources(), 1, "queued with us, hung up");
}

/// A worker's hello names its client on that worker's own diagnostics row:
/// the identification lands on the slot the peer holds, not a neighbour's.
#[test]
fn a_hello_names_its_client_on_the_workers_own_slot() {
    let mut state = two_peer_state();
    let software = hello_software();
    let decisions = state.on_worker_event(
        peer(2),
        PeerWorkerEvent::Identified {
            user_hash: rmule_primitives::UserHash::from_bytes([0x22; 16]),
            crypt: None,
            software: software.clone(),
        },
    );
    let identified: Vec<_> = decisions
        .iter()
        .filter_map(|d| match d {
            Decision::Identify { slot, software } => Some((*slot, software.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(identified, vec![(slot(1), software)]);
}

/// A pre-0.42 mule's `OP_EMULEINFO` arrives after its hello: the version
/// it names replaces the row's Software on the same worker's slot.
#[test]
fn a_software_revision_renames_the_workers_own_slot() {
    let mut state = two_peer_state();
    let _ = state.on_worker_event(
        peer(2),
        PeerWorkerEvent::Identified {
            user_hash: rmule_primitives::UserHash::from_bytes([0x22; 16]),
            crypt: None,
            software: hello_software(),
        },
    );
    let mut evidence = rmule_peer::SoftwareEvidence::default();
    evidence.hello(
        &rmule_peer::PeerHelloBody {
            user_hash: rmule_primitives::UserHash::from_bytes([0x22; 16]),
            client_id: rmule_primitives::ClientId::from_u32(0),
            tcp_port: 0,
            tags: vec![rmule_primitives::Tag::new(
                rmule_primitives::TagName::compact_id(0x01),
                rmule_primitives::TagValue::String(rmule_primitives::Ed2kText::from_utf8("old")),
            )],
            connected_server: rmule_primitives::Ipv4Endpoint::new(
                std::net::Ipv4Addr::UNSPECIFIED,
                0,
            ),
        },
        rmule_peer::HelloTrailer::Absent,
    );
    let revised = evidence.software();
    let decisions = state.on_worker_event(
        peer(2),
        PeerWorkerEvent::SoftwareRevised {
            software: revised.clone(),
        },
    );
    let identified: Vec<_> = decisions
        .iter()
        .filter_map(|d| match d {
            Decision::Identify { slot, software } => Some((*slot, software.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(identified, vec![(slot(1), revised)]);
    assert!(
        state
            .on_worker_event(
                peer(9),
                PeerWorkerEvent::SoftwareRevised {
                    software: hello_software()
                }
            )
            .is_empty(),
        "no worker, no row to rename"
    );
}
