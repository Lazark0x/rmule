//! Engine-half unit tests: opcode routing and wind-down, the `0x97` challenge
//! gate into the capability store, the `0xA2`/`0xA3` description chain, and
//! the dual-path crypt receive (crypt-ping offset, obfuscation-key port,
//! plaintext bypass).

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use rmule_ed2k::ServerUdpFlags;
use rmule_primitives::{DatagramNonce, Packet, encrypt_datagram_server};

use super::super::tests::{ScriptedTransport, fixed_entropy, scripted, stat_res_datagram};
use super::*;
use crate::server_list::test_facts;

mod saved_crypt;

#[tokio::test]
async fn routes_by_opcode_and_drops_what_has_no_consumer() {
    let src = Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4665);
    let sources_datagram = Packet::new(
        PacketProtocol::Edonkey,
        Opcode::GlobFoundSources.as_u8(),
        vec![0xAA],
    )
    .encode_udp();
    let search_datagram = Packet::new(
        PacketProtocol::Edonkey,
        Opcode::GlobSearchRes.as_u8(),
        vec![0x01],
    )
    .encode_udp();
    let (engine, mut inboxes) = ServerUdpEngine::new(
        scripted(vec![
            // Shorter than the two-byte UDP header.
            (vec![PacketProtocol::Edonkey.as_byte()], src),
            // Not eD2k-framed (an obfuscated/foreign protocol byte).
            (vec![0xE5, Opcode::GlobFoundSources.as_u8(), 0x01], src),
            // eD2k-framed but no consumer (`0x9E` UDP callback-fail has
            // no consumer on this surface).
            (
                Packet::new(PacketProtocol::Edonkey, 0x9E, vec![0x01]).encode_udp(),
                src,
            ),
            (search_datagram.clone(), src),
            (sources_datagram.clone(), src),
        ]),
        StatusChallenges::default(),
        SharedServerCapabilities::default(),
        test_facts(&[]).0,
        fixed_entropy,
        false,
        crate::diagnostics::DiagnosticsState::new(),
    );
    let engine_task = tokio::spawn(engine.run());

    // Each consumer sees only its opcode's datagrams, in arrival order.
    let routed = tokio::time::timeout(Duration::from_secs(2), inboxes.sources.recv())
        .await
        .expect("the sources datagram routed within 2s");
    assert_eq!(routed, Some((sources_datagram, src)));
    let routed = tokio::time::timeout(Duration::from_secs(2), inboxes.search.recv())
        .await
        .expect("the search datagram routed within 2s");
    assert_eq!(routed, Some((search_datagram, src)));

    // The exhausted script closes the transport; the engine ends and its
    // dropped senders wind every consumer down.
    let closed = tokio::time::timeout(Duration::from_secs(2), inboxes.sources.recv())
        .await
        .expect("the inbox closed within 2s");
    assert_eq!(closed, None);
    engine_task.await.expect("the engine task ended cleanly");
}

#[tokio::test]
async fn a_challenge_gated_status_reply_populates_the_capability_store() {
    // The reply arrives from the server's UDP port (TCP 4661 + 4); the
    // store keys on its TCP endpoint, the ping-side key.
    let server = Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4661);
    let udp_src = Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4665);
    let challenges = StatusChallenges::default();
    challenges.expect(server, 0x55AA_0007);
    let capabilities = SharedServerCapabilities::default();

    let (engine, _inboxes) = ServerUdpEngine::new(
        scripted(vec![(stat_res_datagram(0x55AA_0007, 1000), udp_src)]),
        challenges.clone(),
        Arc::clone(&capabilities),
        test_facts(&[]).0,
        fixed_entropy,
        false,
        crate::diagnostics::DiagnosticsState::new(),
    );
    // The scripted transport closes after its last datagram, so the run
    // ends deterministically with every datagram consumed.
    engine.run().await;

    let stored = capabilities
        .lock()
        .unwrap()
        .get(&server)
        .expect("a gated reply populates the store under the TCP endpoint")
        .clone();
    assert_eq!(stored.users, 1000);
    assert_eq!(stored.files, 2000);
    assert_eq!(stored.max_users, Some(3000));
    assert!(
        stored
            .udp_flags
            .expect("a 28-byte body carries flags")
            .supports_ext_get_sources2(),
        "the 0x94-upgrade gate reads this bit"
    );
    assert_eq!(stored.udp_crypt, None, "a 28-byte body has no key");
    // The challenge was settled: replaying the same reply gates out.
    assert!(challenges.settle(server, 0x55AA_0007).is_none());
}

#[tokio::test]
async fn a_forged_challenge_neither_mutates_the_store_nor_burns_the_ping() {
    let server = Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4661);
    let udp_src = Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4665);
    let challenges = StatusChallenges::default();
    challenges.expect(server, 0x55AA_0007);
    let capabilities = SharedServerCapabilities::default();

    // A forged reply (wrong challenge) first, then the genuine one: the
    // forgery must not inject its record (users 666) nor consume the
    // outstanding challenge — the genuine reply still lands after it.
    let (engine, _inboxes) = ServerUdpEngine::new(
        scripted(vec![
            (stat_res_datagram(0x55AA_0BAD, 666), udp_src),
            (stat_res_datagram(0x55AA_0007, 1000), udp_src),
        ]),
        challenges,
        Arc::clone(&capabilities),
        test_facts(&[]).0,
        fixed_entropy,
        false,
        crate::diagnostics::DiagnosticsState::new(),
    );
    engine.run().await;

    let stored = capabilities
        .lock()
        .unwrap()
        .get(&server)
        .expect("the genuine reply landed")
        .clone();
    assert_eq!(stored.users, 1000, "the forged record never entered");
}

#[tokio::test]
async fn a_status_reply_with_no_outstanding_ping_is_dropped() {
    let udp_src = Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4665);
    let capabilities = SharedServerCapabilities::default();
    // No `expect` was registered — an unknown/unpinged server's reply
    // (or one from a source below the UDP offset) must not enter.
    let (engine, _inboxes) = ServerUdpEngine::new(
        scripted(vec![
            (stat_res_datagram(0x55AA_0007, 1000), udp_src),
            (
                stat_res_datagram(0x55AA_0007, 1000),
                Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 2),
            ),
        ]),
        StatusChallenges::default(),
        Arc::clone(&capabilities),
        test_facts(&[]).0,
        fixed_entropy,
        false,
        crate::diagnostics::DiagnosticsState::new(),
    );
    engine.run().await;

    assert!(capabilities.lock().unwrap().is_empty());
}

/// An engine over an empty script plus its shared handles — the desc
/// tests step `demux` directly so they can interleave challenge
/// registration with replies.
fn stepping_engine() -> (
    ServerUdpEngine<Arc<ScriptedTransport>>,
    Arc<ScriptedTransport>,
    StatusChallenges,
    SharedServerCapabilities,
) {
    let transport = Arc::new(scripted(vec![]));
    let challenges = StatusChallenges::default();
    let capabilities = SharedServerCapabilities::default();
    let (engine, _inboxes) = ServerUdpEngine::new(
        Arc::clone(&transport),
        challenges.clone(),
        Arc::clone(&capabilities),
        test_facts(&[]).0,
        fixed_entropy,
        false,
        crate::diagnostics::DiagnosticsState::new(),
    );
    (engine, transport, challenges, capabilities)
}

/// A tagged `0xA3` echoing `challenge` and carrying a name +
/// description.
fn desc_res_datagram(challenge: u32) -> Vec<u8> {
    let mut datagram = vec![
        PacketProtocol::Edonkey.as_byte(),
        Opcode::ServerDescRes.as_u8(),
    ];
    datagram.extend_from_slice(&challenge.to_le_bytes());
    datagram.extend_from_slice(&2_u32.to_le_bytes());
    for (id, value) in [(0x01_u8, "Lugdunum"), (0x0B, "a test server")] {
        datagram.extend_from_slice(
            &rmule_primitives::Tag::new(
                rmule_primitives::TagName::compact_id(id),
                rmule_primitives::TagValue::String(rmule_primitives::Ed2kText::from_utf8(value)),
            )
            .encode(),
        );
    }
    datagram
}

#[tokio::test]
async fn a_valid_status_reply_fires_the_desc_request_on_every_other_ping() {
    // aMule's `lastdescpingedcout` alternation: the desc-req rides the
    // 1st, 3rd, 5th… valid `0x97` (increment, fire while < 2, reset on
    // the reply that reaches it).
    let server = Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4661);
    let udp_src = Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4665);
    let (engine, transport, challenges, _capabilities) = stepping_engine();

    for _ in 0..3 {
        challenges.expect(server, 0x55AA_0007);
        engine
            .demux(stat_res_datagram(0x55AA_0007, 1000), udp_src)
            .await;
    }

    let sends = transport.sends.lock().unwrap().clone();
    assert_eq!(sends.len(), 2, "pings 1 and 3 fire, ping 2 skips");
    for (endpoint, datagram) in &sends {
        assert_eq!(
            (endpoint.host(), endpoint.port()),
            ("127.0.0.1", 4661),
            "the desc-req targets the server's TCP endpoint (transport owns the UDP offset)"
        );
        assert_eq!(
            datagram,
            &vec![0xE3, 0xA2, 0xFF, 0xF0, 0xCD, 0xAB],
            "the golden OP_SERVER_DESC_REQ emit under the fixed entropy"
        );
    }
}

#[tokio::test]
async fn the_desc_chain_lands_display_fields_that_survive_a_status_re_ping() {
    let server = Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4661);
    let udp_src = Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4665);
    let (engine, transport, challenges, capabilities) = stepping_engine();

    // 0x97 → the engine fires 0xA2 (challenge 0xABCD_F0FF under the
    // fixed entropy) → the server's tagged 0xA3 echoes it.
    challenges.expect(server, 0x55AA_0007);
    engine
        .demux(stat_res_datagram(0x55AA_0007, 1000), udp_src)
        .await;
    assert_eq!(transport.sends.lock().unwrap().len(), 1, "0xA2 fired");
    engine.demux(desc_res_datagram(0xABCD_F0FF), udp_src).await;

    {
        let store = capabilities.lock().unwrap();
        let record = store.get(&server).expect("the 0x97 record exists");
        assert_eq!(record.display.name.as_deref(), Some("Lugdunum"));
        assert_eq!(record.display.description.as_deref(), Some("a test server"));
        assert_eq!(record.users, 1000, "status fields intact");
    }

    // A later 0x97 refreshes the counts without wiping the display
    // strings (the merge the store's one-record shape demands).
    challenges.expect(server, 0x55AA_0007);
    engine
        .demux(stat_res_datagram(0x55AA_0007, 1234), udp_src)
        .await;
    let store = capabilities.lock().unwrap();
    let record = store.get(&server).expect("the record survives");
    assert_eq!(record.users, 1234, "the re-ping refreshed the counts");
    assert_eq!(
        record.display.name.as_deref(),
        Some("Lugdunum"),
        "the display fields survived the re-ping"
    );
}

#[tokio::test]
async fn a_desc_reply_must_echo_the_outstanding_challenge() {
    let server = Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4661);
    let udp_src = Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4665);
    let (engine, _transport, challenges, capabilities) = stepping_engine();

    challenges.expect(server, 0x55AA_0007);
    engine
        .demux(stat_res_datagram(0x55AA_0007, 1000), udp_src)
        .await;

    // A wrong echo (aMule's multi-homed double answer, or a forgery)
    // mutates nothing and leaves the challenge standing…
    engine.demux(desc_res_datagram(0x0BAD_F0FF), udp_src).await;
    assert_eq!(
        capabilities.lock().unwrap().get(&server).unwrap().display,
        rmule_ed2k::ServerDescTags::default(),
        "the mismatched reply landed nothing"
    );
    // …so the genuine answer still lands after it.
    engine.demux(desc_res_datagram(0xABCD_F0FF), udp_src).await;
    assert_eq!(
        capabilities
            .lock()
            .unwrap()
            .get(&server)
            .unwrap()
            .display
            .name
            .as_deref(),
        Some("Lugdunum")
    );
    // And the settled challenge is one-shot: a replay is silent again.
    capabilities
        .lock()
        .unwrap()
        .get_mut(&server)
        .unwrap()
        .display = Default::default();
    engine.demux(desc_res_datagram(0xABCD_F0FF), udp_src).await;
    assert_eq!(
        capabilities.lock().unwrap().get(&server).unwrap().display,
        rmule_ed2k::ServerDescTags::default(),
        "one answer per ask (aMule zeroes the challenge)"
    );
}

#[tokio::test]
async fn a_legacy_desc_reply_updates_only_a_proven_server() {
    let server = Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4661);
    let udp_src = Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4665);
    let (engine, _transport, challenges, capabilities) = stepping_engine();

    let mut legacy = vec![
        PacketProtocol::Edonkey.as_byte(),
        Opcode::ServerDescRes.as_u8(),
    ];
    legacy.extend_from_slice(&4_u16.to_le_bytes());
    legacy.extend_from_slice(b"desc");
    legacy.extend_from_slice(&4_u16.to_le_bytes());
    legacy.extend_from_slice(b"name");

    // No 0x97-proven record yet: the unsolicited legacy reply drops.
    engine.demux(legacy.clone(), udp_src).await;
    assert!(capabilities.lock().unwrap().is_empty());

    challenges.expect(server, 0x55AA_0007);
    engine
        .demux(stat_res_datagram(0x55AA_0007, 1000), udp_src)
        .await;
    engine.demux(legacy, udp_src).await;
    let store = capabilities.lock().unwrap();
    let display = &store.get(&server).unwrap().display;
    // aMule 2.3.3's assignment: first string → description, second →
    // name (the pinned code path, not the opcode comment).
    assert_eq!(display.description.as_deref(), Some("desc"));
    assert_eq!(display.name.as_deref(), Some("name"));
}

/// A crypt-enabled stepping engine (dual-path receive armed); the desc-style
/// direct-`demux` harness with `crypt_enabled = true`.
fn crypt_engine() -> (
    ServerUdpEngine<Arc<ScriptedTransport>>,
    StatusChallenges,
    SharedServerCapabilities,
) {
    crypt_engine_over(test_facts(&[]).0, None)
}

/// [`crypt_engine`] over the list `facts` holds, keying under the public
/// IPv4 `own` (none known when `None`).
fn crypt_engine_over(
    facts: ServerFacts,
    own: Option<Ipv4Addr>,
) -> (
    ServerUdpEngine<Arc<ScriptedTransport>>,
    StatusChallenges,
    SharedServerCapabilities,
) {
    let transport = Arc::new(scripted(vec![]));
    let challenges = StatusChallenges::default();
    let capabilities = SharedServerCapabilities::default();
    let identity = crate::own_identity::SharedOwnIdentity::default();
    if let Some(ip) = own {
        identity
            .addresses()
            .observe(crate::address_learning::AddressObservation::server_high_id(
                ip,
            ));
    }
    let (engine, _inboxes) = ServerUdpEngine::new(
        transport,
        challenges.clone(),
        Arc::clone(&capabilities),
        facts,
        fixed_entropy,
        true,
        crate::diagnostics::DiagnosticsState::new(),
    );
    (engine.keyed_under(identity), challenges, capabilities)
}

/// The crypt facts of a status answer advertising `obf_port` and key
/// `0xABCD_1234`, learned while our public IPv4 was `key_ip`.
fn saved_crypt(obf_port: u16, key_ip: Option<Ipv4Addr>) -> crate::server_list::ServerUdpCrypt {
    crate::server_list::ServerUdpCrypt {
        obfuscation_udp_port: obf_port,
        obfuscation_tcp_port: 4662,
        udp_key: 0xABCD_1234,
        key_ip,
    }
}

/// One server→client encrypted `0x97`, keyed on `base_key` — the primitive
/// loopback the live capture will replace (ADR-0046 evidence: deterministic
/// tier via the datagram-crypt primitive, `[pending]` byte facts capture-gated).
fn encrypted_stat_res(challenge: u32, users: u32, base_key: u32) -> Vec<u8> {
    encrypt_datagram_server(
        &stat_res_datagram(challenge, users),
        base_key,
        ServerCryptDirection::FromServer,
        &DatagramNonce {
            marker_byte: 0x00,
            random_key: 0x1234,
            padding: vec![0x11, 0x22],
        },
    )
}

#[tokio::test]
async fn a_crypt_ping_reply_decrypts_and_settles_from_the_obfuscation_offset() {
    // The reply arrives from TCP+12 (the crypt-ping port), encrypted under
    // the crypt-ping challenge; the engine maps it back and gates on it.
    let server = Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4661);
    let udp_src = Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4661 + 12);
    let (engine, challenges, capabilities) = crypt_engine();
    challenges.expect_crypt(server, 0x0BAD_F00D);

    engine
        .demux(encrypted_stat_res(0x0BAD_F00D, 1000, 0x0BAD_F00D), udp_src)
        .await;

    assert_eq!(
        capabilities.lock().unwrap().get(&server).map(|c| c.users),
        Some(1000),
        "the decrypted 0x97 populated the store under the TCP endpoint"
    );
    assert!(
        challenges.settle(server, 0x0BAD_F00D).is_none(),
        "the challenge was one-shot settled"
    );
}

/// While a crypt-ping is pending, its challenge keys the reply from any of
/// the three ports both references resolve a server by (aMule
/// `ServerUDPSocket.cpp:80-92` + `ServerList.cpp:643-654`, kno's fork; eMule
/// `UDPSocket.cpp:159-166`): TCP + 4, and the advertised obfuscation port
/// even though the server's `ServerUDPKey` is known.
#[tokio::test]
async fn a_crypt_ping_reply_is_keyed_on_its_challenge_from_every_server_port() {
    let server = Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4661);
    let obf_port = 4675;
    for (from, users) in [(4661 + 4, 700), (obf_port, 800)] {
        let (engine, challenges, capabilities) = crypt_engine();
        let mut record =
            crate::server_capabilities::test_record_with_flags(ServerUdpFlags::UDPOBFUSCATION);
        record.udp_crypt = Some(saved_crypt(obf_port, None));
        capabilities.lock().unwrap().insert(server, record);
        challenges.expect_crypt(server, 0x0BAD_F00D);

        engine
            .demux(
                encrypted_stat_res(0x0BAD_F00D, users, 0x0BAD_F00D),
                Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, from),
            )
            .await;

        assert_eq!(
            capabilities.lock().unwrap().get(&server).map(|c| c.users),
            Some(users),
            "a crypt-ping reply from port {from} decrypted under the challenge"
        );
        assert!(!challenges.crypt_outstanding(server), "and settled it");
    }
}

#[tokio::test]
async fn an_obfuscation_key_reply_decrypts_from_the_advertised_port() {
    // After a server proves ServerUDPKey + SupportsObfuscationUDP, an
    // encrypted reply from its advertised obfuscation UDP port decrypts on
    // that key (aMule's `ServerKeyUDP != 0 && SupportsObfuscationUDP` path).
    let server = Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4661);
    let obf_port = 9999;
    let udp_src = Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, obf_port);
    let ours = Ipv4Addr::new(203, 0, 113, 9);
    let (engine, challenges, capabilities) = crypt_engine_over(test_facts(&[]).0, Some(ours));
    // A prior 0x97 left the key + advertised port + the obfuscation bit,
    // learned under the address we still hold.
    let mut record =
        crate::server_capabilities::test_record_with_flags(ServerUdpFlags::UDPOBFUSCATION);
    record.udp_crypt = Some(saved_crypt(obf_port, Some(ours)));
    capabilities.lock().unwrap().insert(server, record);
    // The encrypted reply echoes an outstanding plain challenge.
    challenges.expect(server, 0x55AA_0042);

    engine
        .demux(encrypted_stat_res(0x55AA_0042, 1000, 0xABCD_1234), udp_src)
        .await;

    assert_eq!(
        capabilities.lock().unwrap().get(&server).map(|c| c.users),
        Some(1000),
        "the ServerUDPKey-decrypted reply refreshed the record"
    );
}

#[tokio::test]
async fn a_plaintext_reply_still_routes_with_crypt_enabled() {
    // The dual-path must not break plaintext: a leading 0xE3 skips decrypt
    // and maps via the plain TCP+4 offset (aMule's `OP_EDONKEYPROT`
    // short-circuit).
    let server = Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4661);
    let udp_src = Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4665);
    let (engine, challenges, capabilities) = crypt_engine();
    challenges.expect(server, 0x55AA_0007);

    engine
        .demux(stat_res_datagram(0x55AA_0007, 1000), udp_src)
        .await;

    assert_eq!(
        capabilities.lock().unwrap().get(&server).map(|c| c.users),
        Some(1000),
    );
}

#[tokio::test]
async fn a_closed_transport_counts_the_engine_going_dark() {
    // The engine's transport is a trait: it reports `None` from `recv`
    // exactly once, whether that is a graceful close or (in production,
    // `RuntimeServerUdpTransport::recv`) the receive-error budget exhausted
    // The engine cannot and does not distinguish the two, so
    // an empty script drives the same wind-down. `run` must count that
    // ending, not only log it: otherwise a dead socket takes
    // global search, get-sources and the status/desc chain down silently.
    let diagnostics = crate::diagnostics::DiagnosticsState::new();
    let (engine, _inboxes) = ServerUdpEngine::new(
        scripted(vec![]),
        StatusChallenges::default(),
        SharedServerCapabilities::default(),
        test_facts(&[]).0,
        fixed_entropy,
        false,
        diagnostics.clone(),
    );

    tokio::time::timeout(Duration::from_secs(2), engine.run())
        .await
        .expect("a closed transport ends the engine's run within 2s");

    assert_eq!(
        diagnostics
            .snapshot()
            .session
            .server_udp_transport_ended_total,
        1
    );
}
