//! Session-level `OP_ANSWERSOURCES` consume (ADR-0055):
//! peer-claimed-nibble threading, provenance survival,
//! sanity filters, Low-ID routing, the per-file cap, and the capture-mode
//! SX1 toggle. The codec-only KATs for the same opcodes live in
//! `source_exchange.rs`; this leg covers only the session wiring above them,
//! over the ADR-0055 receive-only baseline.

use std::net::Ipv4Addr;

use rmule_peer::{
    AnswerSources, Hello, HelloAnswer, MiscOptions1, MiscOptions2, ModMiscOptions, PeerCommand,
    PeerEvent, PeerHelloBody, PeerOutput, PeerSession, RequesterCommand, RequesterEvent,
    SourceExchangeEntry, SourceExchangeVersion,
};
use rmule_primitives::session::drain;
use rmule_primitives::{
    ClientId, CryptStance, Ed2kText, FileHash, Ipv4Endpoint, OutboundCrypt, Packet, PacketProtocol,
    PeerSource, SourceCryptOptions, SourceSighting, Tag, TagName, TagValue, UserHash,
};
use rmule_testkit::peer_session::{ctx, events, file_hash, last_write_bytes, peer_at, writes};

/// Our own stance for these session tests: supports and requests obfuscation
/// (the "someone has to ask" half of `PeerCrypt::outbound`).
const OURS: CryptStance = CryptStance::new(true, true, false);

/// A peer hello answer advertising `source_exchange_nibble` in its
/// `CT_EMULE_MISCOPTIONS1` tag — the value `AnswerSources::decode_packet`'s
/// geometry cross-check resolves against, the peer's own claim rather than
/// rmule's advertised nibble (ADR-0055).
fn answer_body(source_exchange_nibble: u8) -> PeerHelloBody {
    PeerHelloBody {
        user_hash: UserHash::from_bytes([0x99; UserHash::BYTE_LEN]),
        client_id: ClientId::from_u32(0x2000_0002),
        tcp_port: 4662,
        tags: vec![
            Tag::new(
                TagName::length_prefixed_id(0x01),
                TagValue::String(Ed2kText::from_utf8("remote")),
            ),
            rmule_testkit::peer_session::mule_version_tag(),
            MiscOptions1::from_bits((u32::from(source_exchange_nibble)) << 12).to_tag(),
        ],
        connected_server: Ipv4Endpoint::new(Ipv4Addr::UNSPECIFIED, 0),
    }
}

fn identified_session(source_exchange_nibble: u8) -> PeerSession {
    let mut session = PeerSession::new_outbound(peer_at(9), ctx());
    session.start();
    drain(|| session.poll_output());
    let answer = HelloAnswer::new(answer_body(source_exchange_nibble))
        .encode_packet()
        .encode();
    session.handle_bytes(&answer);
    drain(|| session.poll_output());
    session
}

/// `identified_session` with `hash`'s file flow open — an
/// answer for a file with no flow is dropped, and these tests' subject is the
/// answer pipeline, not that gate. The name ask opens the flow, because a
/// nibble-1 peer is never asked for sources (ADR-0108) while its answer
/// geometry is still read.
fn solicited_session(source_exchange_nibble: u8, hash: FileHash) -> PeerSession {
    let mut session = identified_session(source_exchange_nibble);
    session.handle_command(PeerCommand::Requester(RequesterCommand::RequestFile {
        file_hash: hash,
        file_size: 4096,
        own_status: rmule_peer::PartBitmap::downloader_empty(4096),
        want_sources: false,
        want_aich_root: false,
    }));
    drain(|| session.poll_output());
    session
}

fn sources_received(outputs: &[PeerOutput], hash: FileHash) -> Option<&[SourceSighting]> {
    events(outputs).into_iter().find_map(|e| match e {
        PeerEvent::Requester(RequesterEvent::SourcesReceived { file_hash, sources })
            if *file_hash == hash =>
        {
            Some(sources.as_slice())
        }
        _ => None,
    })
}

/// A v1 `OP_ANSWERSOURCES` payload with an explicit per-source server
/// endpoint — unlike the plain codec's `encode_packet` (which always writes
/// zero there), this lets the Low-ID
/// routing rule's server-match be exercised end to end over the wire.
fn v1_answer_sources_with_server(hash: FileHash, sources: &[(u32, u16, Ipv4Endpoint)]) -> Vec<u8> {
    let mut payload = hash.as_bytes().to_vec();
    payload.extend_from_slice(&(sources.len() as u16).to_le_bytes());
    for &(id, tcp_port, server) in sources {
        payload.extend_from_slice(&id.to_le_bytes());
        payload.extend_from_slice(&tcp_port.to_le_bytes());
        payload.extend_from_slice(&server.ip.octets());
        payload.extend_from_slice(&server.port.to_le_bytes());
    }
    Packet::new(PacketProtocol::Emule, 0x82, payload).encode()
}

/// Peer-nibble threading (ADR-0055): this peer advertised source-exchange
/// nibble **3**. A v3-shaped (28-byte stride) answer only resolves when the
/// cross-check version exceeds 2 (`resolve_sx1_version`) — cross-checked
/// against a nibble of 1 instead, it would be rejected and the session would
/// close as a protocol violation. Threading the peer's own claimed nibble is
/// what makes this resolve.
#[test]
fn peer_claimed_nibble_resolves_a_v3_answer_a_nibble_of_one_would_reject() {
    let h = file_hash(0x10);
    let mut session = solicited_session(3, h);
    let id = u32::from_le_bytes([1, 2, 3, 4]); // High-ID 1.2.3.4, ed2k order
    let source = SourceSighting::plain(PeerSource::new(ClientId::from_u32(id), 4662));
    let packet = AnswerSources {
        file_hash: h,
        sources: vec![SourceExchangeEntry::plain(source)],
    }
    .encode_packet(SourceExchangeVersion::V3);

    session.handle_bytes(&packet.encode());
    let out = drain(|| session.poll_output());

    let sources = sources_received(&out, h).expect("SourcesReceived emitted, session stayed open");
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].client_id(), Some(ClientId::from_u32(id)));
    assert!(
        !out.iter().any(|o| matches!(o, PeerOutput::Close(_))),
        "a resolvable v3 answer never closes the session"
    );
}

/// A malformed `OP_ANSWERSOURCES` (here a truncated source list) is a
/// non-terminal drop, not a protocol violation: aMule's `AddClientSources`
/// silently ignores it (`PartFile.cpp` @4e8f2b3c). The session must stay open
/// and surface a `SourceExchangeAnswerSkipped` diagnostic rather than tearing
/// down an otherwise-healthy — possibly actively downloading — peer.
#[test]
fn a_malformed_answer_sources_is_dropped_without_closing_the_session() {
    let mut session = identified_session(1);
    let h = file_hash(0x20);
    // Declares 200 sources but supplies almost no body — unresolvable at any
    // stride, so the decoder errors instead of producing an `AnswerSources`.
    let payload = {
        let mut p = h.as_bytes().to_vec();
        p.extend_from_slice(&200u16.to_le_bytes());
        p.extend_from_slice(&[0xAB, 0xCD, 0xEF]);
        p
    };
    session.handle_bytes(&Packet::new(PacketProtocol::Emule, 0x82, payload).encode());
    let out = drain(|| session.poll_output());

    assert!(
        !out.iter().any(|o| matches!(o, PeerOutput::Close(_))),
        "a malformed source answer never closes the session"
    );
    assert!(
        events(&out).iter().any(|e| matches!(
            e,
            PeerEvent::Requester(RequesterEvent::SourceExchangeAnswerSkipped { .. })
        )),
        "the drop surfaces a diagnostic instead of a silent close: {:?}",
        events(&out)
    );
}

/// Provenance threading (ADR-0046 model): a v4 source that both carries a User
/// Hash and advertises crypt support survives the consume-side filter with
/// that provenance intact, landing in the same `SourceSighting::peer_crypt`
/// model the server `0x44` path feeds (ADR-0046/ADR-0049).
#[test]
fn crypt_capable_v4_source_keeps_its_obfuscation_dial_hash_after_the_filter() {
    let h = file_hash(0x11);
    let mut session = solicited_session(4, h);
    let id = u32::from_le_bytes([9, 8, 7, 6]); // High-ID, ed2k order
    let hash = UserHash::from_bytes([0xAB; UserHash::BYTE_LEN]);
    let crypt = SourceCryptOptions::from_byte(0b001); // supports_crypt
    let source = SourceSighting::new(
        PeerSource::new(ClientId::from_u32(id), 4662),
        Some(hash),
        Some(crypt),
    );
    let packet = AnswerSources {
        file_hash: h,
        sources: vec![SourceExchangeEntry::plain(source)],
    }
    .encode_packet(SourceExchangeVersion::V4);

    session.handle_bytes(&packet.encode());
    let out = drain(|| session.poll_output());

    let sources = sources_received(&out, h).expect("SourcesReceived emitted");
    assert_eq!(sources.len(), 1);
    assert_eq!(
        sources[0].peer_crypt().outbound(OURS),
        OutboundCrypt::Obfuscated { toward: hash },
        "crypt-capable + hash-carrying source is obfuscate-dialable after the filter"
    );
}

/// Sanity filter: a High-ID entry that is a 0-IP, loopback, or echoes our own
/// endpoint back is dropped from the candidates the event surfaces.
#[test]
fn sanity_filter_drops_zero_ip_loopback_and_own_endpoint_high_ids() {
    let h = file_hash(0x12);
    let mut session = solicited_session(1, h);
    let zero_ip = u32::from_le_bytes([0, 9, 9, 9]);
    let loopback = u32::from_le_bytes([127, 0, 0, 1]);
    let own = 0x1000_0001; // exactly ctx()'s own client id / port
    let sane = u32::from_le_bytes([1, 2, 3, 4]);
    let payload = {
        let mut p = h.as_bytes().to_vec();
        p.extend_from_slice(&4u16.to_le_bytes());
        for id in [zero_ip, loopback, own, sane] {
            p.extend_from_slice(&id.to_le_bytes());
            p.extend_from_slice(&4662u16.to_le_bytes());
            p.extend_from_slice(&0u32.to_le_bytes());
            p.extend_from_slice(&0u16.to_le_bytes());
        }
        p
    };
    session.handle_bytes(&Packet::new(PacketProtocol::Emule, 0x82, payload).encode());
    let out = drain(|| session.poll_output());

    let sources = sources_received(&out, h).expect("SourcesReceived emitted");
    assert_eq!(
        sources
            .iter()
            .copied()
            .map(SourceSighting::client_id)
            .collect::<Vec<_>>(),
        vec![Some(ClientId::from_u32(sane))],
        "only the sane High-ID survives; 0-IP/loopback/own-endpoint are dropped"
    );
}

/// Low-ID routing: kept as a candidate (dialable via the existing
/// server-callback path) only when its declared server matches our own
/// connected server; otherwise parked (dropped from this event).
#[test]
fn low_id_routing_keeps_matching_server_and_parks_the_rest() {
    let h = file_hash(0x13);
    let mut session = solicited_session(1, h);
    let connected = Ipv4Endpoint::new(Ipv4Addr::new(192, 0, 2, 1), 4661); // ctx()'s connected_server
    let elsewhere = Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 9), 4661);
    let unspecified = Ipv4Endpoint::new(Ipv4Addr::UNSPECIFIED, 0);

    let wire = v1_answer_sources_with_server(
        h,
        &[
            (5000, 4662, connected),   // matches our connected server: kept
            (5001, 4662, elsewhere),   // different server: parked
            (5002, 4662, unspecified), // no server declared: parked
        ],
    );
    session.handle_bytes(&wire);
    let out = drain(|| session.poll_output());

    let sources = sources_received(&out, h).expect("SourcesReceived emitted");
    assert_eq!(
        sources
            .iter()
            .copied()
            .map(SourceSighting::client_id)
            .collect::<Vec<_>>(),
        vec![Some(ClientId::from_u32(5000))],
        "only the Low-ID declaring our connected server is kept"
    );
}

/// The per-file cap is honored cumulatively across separate answers for the
/// same file, not reset per packet.
#[test]
fn per_file_cap_is_honored_cumulatively_across_answers() {
    let h = file_hash(0x14);
    let mut session = solicited_session(1, h);

    // First answer: a handful of sane High-ID sources, well under any
    // plausible cap — all survive.
    let first_ids: Vec<u32> = (0..5)
        .map(|i| u32::from_le_bytes([1, 2, 3, i + 1]))
        .collect();
    let first_payload = {
        let mut p = h.as_bytes().to_vec();
        p.extend_from_slice(&(first_ids.len() as u16).to_le_bytes());
        for id in &first_ids {
            p.extend_from_slice(&id.to_le_bytes());
            p.extend_from_slice(&4662u16.to_le_bytes());
            p.extend_from_slice(&0u32.to_le_bytes());
            p.extend_from_slice(&0u16.to_le_bytes());
        }
        p
    };
    session.handle_bytes(&Packet::new(PacketProtocol::Emule, 0x82, first_payload).encode());
    let out1 = drain(|| session.poll_output());
    let first = sources_received(&out1, h).expect("first SourcesReceived emitted");
    assert_eq!(first.len(), 5);

    // A distinct file is entirely unaffected by the first file's running
    // count — the cap is per file, not global.
    let other_hash = file_hash(0x15);
    session.handle_command(PeerCommand::Requester(RequesterCommand::RequestFile {
        file_hash: other_hash,
        file_size: 4096,
        own_status: rmule_peer::PartBitmap::downloader_empty(4096),
        want_sources: false,
        want_aich_root: false,
    }));
    drain(|| session.poll_output());
    let other_id = u32::from_le_bytes([9, 9, 9, 9]);
    let other_payload = {
        let mut p = other_hash.as_bytes().to_vec();
        p.extend_from_slice(&1u16.to_le_bytes());
        p.extend_from_slice(&other_id.to_le_bytes());
        p.extend_from_slice(&4662u16.to_le_bytes());
        p.extend_from_slice(&0u32.to_le_bytes());
        p.extend_from_slice(&0u16.to_le_bytes());
        p
    };
    session.handle_bytes(&Packet::new(PacketProtocol::Emule, 0x82, other_payload).encode());
    let out2 = drain(|| session.poll_output());
    let other = sources_received(&out2, other_hash).expect("second file's SourcesReceived emitted");
    assert_eq!(
        other.len(),
        1,
        "a different file's cap tracking is independent"
    );
}

/// The capture-mode SX1 toggle (ADR-0055 evidence): overrides the *outbound*
/// hello's advertised source-exchange nibble to 3 (aMule's own default)
/// instead of the registry's honest 1 — the "consume `0x82` v3" capture
/// recipe needs this so a real aMule's SX1 serve path answers at v3 geometry.
#[test]
fn capture_override_advertises_nibble_three_in_the_outbound_hello() {
    let mut session =
        PeerSession::new_outbound(peer_at(9), ctx()).with_source_exchange_capture_override(3);
    session.start();
    let out = drain(|| session.poll_output());

    let write = out
        .iter()
        .find_map(|o| match o {
            PeerOutput::Write(bytes) => Some(bytes.clone()),
            _ => None,
        })
        .expect("OP_HELLO written");
    let (packet, _) = Packet::decode(&write).expect("hello frame decodes");
    let hello = Hello::decode_packet(&packet).expect("OP_HELLO decodes");
    let misc = MiscOptions1::from_tags(&hello.body().tags).expect("hello carries MiscOptions1");
    assert_eq!(misc.source_exchange_version(), 3);
}

/// Without the capture override, the hello advertises the registry's honest
/// nibble — aMule's own 3 (ADR-0055), so the diagnostic override to 3
/// coincides with the honest default.
/// The toggle stays opt-in machinery, never forcing a value the registry did
/// not already choose.
#[test]
fn without_the_capture_override_the_hello_stays_honestly_advertised() {
    let mut session = PeerSession::new_outbound(peer_at(9), ctx());
    session.start();
    let out = drain(|| session.poll_output());

    let write = out
        .iter()
        .find_map(|o| match o {
            PeerOutput::Write(bytes) => Some(bytes.clone()),
            _ => None,
        })
        .expect("OP_HELLO written");
    let (packet, _) = Packet::decode(&write).expect("hello frame decodes");
    let hello = Hello::decode_packet(&packet).expect("OP_HELLO decodes");
    let misc = MiscOptions1::from_tags(&hello.body().tags).expect("hello carries MiscOptions1");
    assert_eq!(misc.source_exchange_version(), 3);
}

// ---------------------------------------------------------------------------
// ADR-0055 requester side: rmule asks an SX2 peer with the `0x83` sub inside
// its multipacket bundle (a standalone ask is always the SX1 `0x81`, as
// `amule_source_ask_capture` pins), and consumes the peer's
// `OP_ANSWERSOURCES2` (0x84) answer through the *same* sanity/provenance/cap
// core as `0x82` (both directions).
// ---------------------------------------------------------------------------

/// A peer hello answer that also advertises `SupportsSourceEx2` (`MiscOptions2`
/// bit 10) alongside its SX1 nibble — the capability rmule's *requester* reads
/// to decide whether its bundled ask carries the `OP_REQUESTSOURCES2` (`0x83`)
/// sub instead of the bare-hash `OP_REQUESTSOURCES` (`0x81`), aMule-exact
/// (`CUpDownClient::SendFileRequest`, `DownloadClient.cpp` @4e8f2b3c).
fn sx2_answer_body(source_exchange_nibble: u8) -> PeerHelloBody {
    let mut body = answer_body(source_exchange_nibble);
    body.tags.push(MiscOptions2::from_bits(1 << 10).to_tag());
    body
}

fn identified_sx2_session(source_exchange_nibble: u8) -> PeerSession {
    let mut session = PeerSession::new_outbound(peer_at(9), ctx());
    session.start();
    drain(|| session.poll_output());
    let answer = HelloAnswer::new(sx2_answer_body(source_exchange_nibble))
        .encode_packet()
        .encode();
    session.handle_bytes(&answer);
    drain(|| session.poll_output());
    session
}

fn solicited_sx2_session(source_exchange_nibble: u8, hash: FileHash) -> PeerSession {
    let mut session = identified_sx2_session(source_exchange_nibble);
    session.handle_command(PeerCommand::Requester(RequesterCommand::RequestSources {
        file_hash: hash,
    }));
    drain(|| session.poll_output());
    session
}

/// A raw v4 `OP_ANSWERSOURCES2` wire frame: `[ver=4][hash16][count]` then per
/// source `[id u32][tcp u16][srvIP u32][srvPort u16][userhash 16][crypt 1]`.
/// `id` is the raw wire value (callers pass an already-swapped HighID for the
/// v>=4 hybrid order).
fn v4_answersources2(hash: FileHash, sources: &[(u32, u16, [u8; 16], u8)]) -> Vec<u8> {
    let mut p = vec![4u8];
    p.extend_from_slice(hash.as_bytes());
    p.extend_from_slice(&(sources.len() as u16).to_le_bytes());
    for &(id, tcp, user_hash, crypt) in sources {
        p.extend_from_slice(&id.to_le_bytes());
        p.extend_from_slice(&tcp.to_le_bytes());
        p.extend_from_slice(&0u32.to_le_bytes()); // server ip
        p.extend_from_slice(&0u16.to_le_bytes()); // server port
        p.extend_from_slice(&user_hash);
        p.push(crypt);
    }
    Packet::new(PacketProtocol::Emule, 0x84, p).encode()
}

/// A peer that does not advertise SX2 is asked with the legacy bare-hash
/// `OP_REQUESTSOURCES` (`0x81`) — rmule never asks SX2 of a client that cannot
/// answer it.
#[test]
fn request_sources_asks_a_non_sx2_peer_with_op_requestsources() {
    let h = file_hash(0x31);
    let mut session = identified_session(3); // MiscOptions1 nibble only, no SX2 bit
    session.handle_command(PeerCommand::Requester(RequesterCommand::RequestSources {
        file_hash: h,
    }));
    let out = drain(|| session.poll_output());

    let (packet, _) = Packet::decode(&last_write_bytes(&out)).expect("request frames");
    assert_eq!(
        packet.opcode(),
        0x81,
        "a non-SX2 peer earns the legacy request"
    );
    assert_eq!(packet.payload(), h.as_bytes(), "0x81 body is the bare hash");
}

/// The requester consume path for `OP_ANSWERSOURCES2` (`0x84`): an SX2 answer
/// to our own `0x83` ask fans in through the *same* sanity-filter / provenance
/// / cap core as `0x82` (ADR-0055 "one semantic core"), surfacing
/// `SourcesReceived`. v4 carries crypt+hash provenance, and a HighID rides
/// hybrid on the wire, so the decoded id must swap back to ed2k order.
#[test]
fn an_answersources2_answer_surfaces_sources_received_with_provenance() {
    let h = file_hash(0x32);
    let mut session = solicited_sx2_session(3, h);
    let ed2k_id = u32::from_le_bytes([1, 2, 3, 4]); // HighID 1.2.3.4, ed2k order
    let user_hash = [0xAB; 16];
    let crypt = 0b001; // supports_crypt
    let wire = v4_answersources2(h, &[(ed2k_id.swap_bytes(), 4662, user_hash, crypt)]);
    session.handle_bytes(&wire);
    let out = drain(|| session.poll_output());

    let sources = sources_received(&out, h).expect("SourcesReceived from a 0x84 answer");
    assert_eq!(sources.len(), 1);
    assert_eq!(
        sources[0].client_id(),
        Some(ClientId::from_u32(ed2k_id)),
        "v4 HighID swaps back from hybrid to ed2k order"
    );
    assert_eq!(
        sources[0].peer_crypt().outbound(OURS),
        OutboundCrypt::Obfuscated {
            toward: UserHash::from_bytes(user_hash),
        },
        "crypt+hash provenance survives the shared consume core"
    );
    assert!(
        !out.iter().any(|o| matches!(o, PeerOutput::Close(_))),
        "a resolvable 0x84 answer never closes the session"
    );
}

/// A malformed `0x84` (geometry not matching its declared version) is a
/// non-terminal drop — aMule's `AddClientSources` silently returns for SX2 too
/// (`PartFile.cpp` @4e8f2b3c) — surfacing `SourceExchangeAnswerSkipped`, never
/// closing an otherwise-healthy link.
#[test]
fn a_malformed_answersources2_is_dropped_without_closing_the_session() {
    let h = file_hash(0x33);
    let mut session = solicited_sx2_session(3, h);
    // version=4 (29-byte stride) but count=2 with only one entry's bytes.
    let mut payload = vec![4u8];
    payload.extend_from_slice(h.as_bytes());
    payload.extend_from_slice(&2u16.to_le_bytes());
    payload.extend_from_slice(&[0u8; 29]);
    session.handle_bytes(&Packet::new(PacketProtocol::Emule, 0x84, payload).encode());
    let out = drain(|| session.poll_output());

    assert!(
        !out.iter().any(|o| matches!(o, PeerOutput::Close(_))),
        "a malformed 0x84 never closes the session"
    );
    assert!(
        events(&out).iter().any(|e| matches!(
            e,
            PeerEvent::Requester(RequesterEvent::SourceExchangeAnswerSkipped { .. })
        )),
        "the drop surfaces a diagnostic instead of a silent close: {:?}",
        events(&out)
    );
}

/// The ADR-0055 baseline every rule above upgrades: `RequestSources` frames
/// `OP_REQUESTSOURCES` for the file, and the peer's plain answer projects
/// one `SourcesReceived`. The peer advertises nibble 2, the lowest aMule asks
/// (stock 2.3.3 `DownloadClient.cpp:191`).
#[test]
fn request_sources_frames_op_requestsources_and_answer_projects_sources_received() {
    let h = file_hash(0x5E);
    let mut session = identified_session(2);

    session.handle_command(PeerCommand::Requester(RequesterCommand::RequestSources {
        file_hash: h,
    }));
    let out = drain(|| session.poll_output());
    assert!(
        writes(&out)
            .iter()
            .any(|p| p.opcode() == 0x81 && p.payload() == h.as_bytes()),
        "OP_REQUESTSOURCES framed for the file"
    );

    // The peer answers with one High-ID source (1.2.3.4:4662).
    let id = u32::from_le_bytes([1, 2, 3, 4]);
    let answer = AnswerSources {
        file_hash: h,
        sources: vec![SourceExchangeEntry::plain(SourceSighting::plain(
            PeerSource::new(ClientId::from_u32(id), 4662),
        ))],
    }
    .encode_packet(SourceExchangeVersion::V2);
    session.handle_bytes(&answer.encode());
    let out2 = drain(|| session.poll_output());
    assert!(events(&out2).iter().any(|e| matches!(
        e,
        PeerEvent::Requester(RequesterEvent::SourcesReceived { file_hash, sources })
            if *file_hash == h && sources.len() == 1 && sources[0].tcp_port() == 4662
    )));
}

/// emule-qt `73fff714`'s ExtSX answer, bench run `1790195410`: one
/// record for a requester that had named `3fff:ed2:1::7` in its hello, with
/// the client id emule-qt writes for a peer that said id 0 — zero, a Low ID
/// no server declared.
const EMULEQT_EXTSX: &[u8] = include_bytes!(
    "../fixtures/source_exchange/captured/emule-qt-73fff714-extsx-ipv6-20260923/\
     emuleqt_op_answersources2_extsx_ipv6.bin"
);

/// ADR-0087 judges an ExtSX record's two families independently: a Low ID no
/// route can reach is parked, but the same record's usable IPv6 is a dialable
/// source in its own right and must reach core as one. Without this, every
/// source emule-qt hands out for a server-less IPv6 peer is lost.
#[test]
fn an_extsx_low_id_record_with_a_usable_ipv6_surfaces_as_its_ipv6() {
    let hash = FileHash::from_bytes(0x879B_7240_FE00_815F_5431_AE70_86B8_C939_u128.to_be_bytes());
    let mut session = PeerSession::new_outbound(peer_at(9), ctx());
    session.start();
    drain(|| session.poll_output());
    let mut body = sx2_answer_body(3);
    body.tags.push(ModMiscOptions::rmule_claim().to_tag());
    session.handle_bytes(&HelloAnswer::new(body).encode_packet().encode());
    drain(|| session.poll_output());
    session.handle_command(PeerCommand::Requester(RequesterCommand::RequestSources {
        file_hash: hash,
    }));
    drain(|| session.poll_output());

    session.handle_bytes(EMULEQT_EXTSX);
    let outputs = drain(|| session.poll_output());
    let sources = sources_received(&outputs, hash).expect("the answer surfaces SourcesReceived");
    let [source] = sources else {
        panic!("the one IPv6-reachable record survives: {sources:?}");
    };
    assert_eq!(
        source
            .as_peer_endpoint()
            .map(|endpoint| endpoint.to_string()),
        Some("[3fff:ed2:1::7]:4662".to_owned()),
    );
    assert_eq!(source.user_hash(), Some(UserHash::from_bytes([0x51; 16])));
}

/// A dual-stack record — a routable IPv4 id with `CT_MOD_IP_V6` beside it —
/// surfaces as **one** source carrying both addresses, never as two: both are
/// the same peer, and the family it is dialed in is the core Dial Chooser's
/// call (ADR-0087), not the reader's. emule-qt's reader makes the same call,
/// one client with its IPv6 set beside the id (`PartFile.cpp:2894-2900`).
#[test]
fn an_extsx_dual_stack_record_surfaces_as_one_source_with_both_addresses() {
    let hash = file_hash(0x5F);
    let mut session = PeerSession::new_outbound(peer_at(9), ctx());
    session.start();
    drain(|| session.poll_output());
    let mut body = sx2_answer_body(3);
    body.tags.push(ModMiscOptions::rmule_claim().to_tag());
    session.handle_bytes(&HelloAnswer::new(body).encode_packet().encode());
    drain(|| session.poll_output());
    session.handle_command(PeerCommand::Requester(RequesterCommand::RequestSources {
        file_hash: hash,
    }));
    drain(|| session.poll_output());

    let v4 = Ipv4Endpoint::new(Ipv4Addr::new(198, 51, 100, 7), 4662);
    let v6 = rmule_primitives::Ipv6Endpoint::new("3fff:ed2:1::7".parse().unwrap(), 4662);
    let dual = SourceSighting::plain(PeerSource::HighId(v4)).with_ipv6_half(Some(v6));
    let answer = rmule_peer::AnswerSources2 {
        version: SourceExchangeVersion::V1,
        file_hash: hash,
        sources: vec![SourceExchangeEntry::plain(dual)],
    }
    .encode_ext_packet(rmule_peer::ExtSxEmission::default());
    session.handle_bytes(&answer.encode());

    let outputs = drain(|| session.poll_output());
    let sources = sources_received(&outputs, hash).expect("the answer surfaces SourcesReceived");
    let [source] = sources else {
        panic!("one peer, one source: {sources:?}");
    };
    assert_eq!(source.peer_source(), Some(PeerSource::HighId(v4)));
    assert_eq!(source.ipv6(), Some(v6));
}

/// aMule asks a peer for sources only when it advertised SourceExchange2 or an
/// SX1 nibble above 1 (stock 2.3.3 `DownloadClient.cpp:191`); rmule's ask follows, on the
/// standalone path and in the connect-time bundle alike (ADR-0108).
#[test]
fn a_peer_below_source_exchange_version_two_is_never_asked_for_sources() {
    let h = file_hash(0x6D);
    for (nibble, asked) in [(0, false), (1, false), (2, true), (3, true)] {
        let mut session = identified_session(nibble);
        session.handle_command(PeerCommand::Requester(RequesterCommand::RequestSources {
            file_hash: h,
        }));
        session.handle_command(PeerCommand::Requester(RequesterCommand::RequestFile {
            file_hash: h,
            file_size: 4096,
            own_status: rmule_peer::PartBitmap::downloader_empty(4096),
            want_sources: true,
            want_aich_root: false,
        }));
        let out = drain(|| session.poll_output());
        let asks = writes(&out).iter().filter(|p| p.opcode() == 0x81).count();
        assert_eq!(asks > 0, asked, "nibble {nibble}: asked {asks} times");
    }
}
