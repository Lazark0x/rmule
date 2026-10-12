//! The seal rule at the engine's own send, the `0xA2` its gated `0x97`
//! fires (aMule `ServerUDPSocket.cpp:248`, then `SendPacket`'s `366-374`):
//! sealed under the server's `ServerUDPKey` to its obfuscation UDP port when
//! the policy is set and the key is one the gate offers, plain at standard
//! port + 4 otherwise. And the sealed answer, from the obfuscation port,
//! opens under the same key.

use super::*;

/// Lugdunum's crypt facts as its crypt-ping answer carries them on the bench
/// (run `1791422886`, decrypted): obfuscation UDP port 4675, TCP 4661.
const OBF_PORT: u16 = 4675;
const KEY: u32 = 0x05A6_8835;
/// The golden `OP_SERVER_DESC_REQ` under the fixed desc entropy.
const DESC_REQ: [u8; 6] = [0xE3, 0xA2, 0xFF, 0xF0, 0xCD, 0xAB];

/// A `0x97` whose 40-byte body carries the crypt facts: UDP obfuscation
/// advertised beside `EXT_GETSOURCES2`, the ports above and [`KEY`].
fn keyed_stat_res(challenge: u32) -> Vec<u8> {
    let mut datagram = vec![
        PacketProtocol::Edonkey.as_byte(),
        Opcode::GlobServStatRes.as_u8(),
    ];
    let flags = ServerUdpFlags::EXT_GETSOURCES2 | ServerUdpFlags::UDPOBFUSCATION;
    for word in [challenge, 3, 3, 1000, 1000, 4000, flags, 0] {
        datagram.extend_from_slice(&word.to_le_bytes());
    }
    datagram.extend_from_slice(&OBF_PORT.to_le_bytes());
    datagram.extend_from_slice(&4661_u16.to_le_bytes());
    datagram.extend_from_slice(&KEY.to_le_bytes());
    datagram
}

/// An engine whose seal is armed by `policy` and keys under `ours`.
fn engine_under(
    policy: Option<rmule_net::peer::ObfuscationPolicy>,
    ours: Ipv4Addr,
) -> (
    ServerUdpEngine<Arc<ScriptedTransport>>,
    Arc<ScriptedTransport>,
    StatusChallenges,
) {
    let transport = Arc::new(scripted(vec![]));
    let own = crate::own_identity::SharedOwnIdentity::default();
    own.addresses()
        .observe(crate::address_learning::AddressObservation::server_high_id(
            ours,
        ));
    let capabilities = SharedServerCapabilities::default();
    let facts = test_facts(&[]).0;
    let seal = seal_over(
        Arc::clone(&transport),
        crate::obfuscation_policy::SharedObfuscationPolicy::new(policy),
        own,
        Arc::clone(&capabilities),
        facts.clone(),
    );
    let challenges = StatusChallenges::default();
    let (engine, _inboxes) = ServerUdpEngine::new(
        Arc::clone(&transport),
        seal,
        challenges.clone(),
        capabilities,
        facts,
        fixed_entropy,
        crate::diagnostics::DiagnosticsState::new(),
    );
    (engine, transport, challenges)
}

/// What went out after the status answer `reply` arrived from standard
/// port + 4: the plain frames, then the obfuscated datagrams, each with its
/// destination.
async fn sent_after(
    policy: Option<rmule_net::peer::ObfuscationPolicy>,
    reply: Vec<u8>,
) -> (Vec<(Ipv4Endpoint, Vec<u8>)>, Vec<(Ipv4Endpoint, Vec<u8>)>) {
    let (engine, transport, challenges) = engine_under(policy, Ipv4Addr::new(203, 0, 113, 3));
    challenges.expect(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4661), 0x55AA_0007);
    engine
        .demux(reply, Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4665))
        .await;
    let plain = transport.sends.lock().unwrap().clone();
    let obfuscated = transport.obfuscated.lock().unwrap().clone();
    (plain, obfuscated)
}

const REQUESTED: Option<rmule_net::peer::ObfuscationPolicy> =
    Some(rmule_net::peer::ObfuscationPolicy::Requested);

/// The bench's case: a server whose answer carried a key, learned under the
/// address we hold, under a set policy. The ask leaves sealed for its
/// obfuscation port and opens under the key in the client-to-server
/// direction to the plain frame; nothing goes to standard port + 4.
#[tokio::test]
async fn a_keyed_servers_ask_is_sealed_to_its_obfuscation_port() {
    let (plain, sealed) = sent_after(REQUESTED, keyed_stat_res(0x55AA_0007)).await;

    assert!(plain.is_empty(), "no plain ask: {plain:?}");
    assert_eq!(sealed.len(), 1);
    let (to, datagram) = &sealed[0];
    assert_eq!(*to, Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, OBF_PORT));
    assert_ne!(datagram[0], 0xE3, "a sealed datagram never reads as plain");
    assert_eq!(
        decrypt_datagram_server(datagram, KEY, ServerCryptDirection::ToServer),
        Some(DESC_REQ.to_vec())
    );
}

/// A server whose answer carried no key is asked plain at standard port + 4
/// under the same set policy.
#[tokio::test]
async fn a_server_without_a_key_is_asked_plain_at_standard_plus_four() {
    let (plain, sealed) = sent_after(REQUESTED, stat_res_datagram(0x55AA_0007, 1000)).await;

    assert!(sealed.is_empty(), "nothing sealed: {sealed:?}");
    assert_eq!(
        plain,
        vec![(
            Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4665),
            DESC_REQ.to_vec()
        )]
    );
}

/// Policy `off` disarms the layer: a keyed server is asked plain at standard
/// port + 4.
#[tokio::test]
async fn policy_off_asks_a_keyed_server_plain() {
    let (plain, sealed) = sent_after(None, keyed_stat_res(0x55AA_0007)).await;

    assert!(sealed.is_empty(), "nothing sealed: {sealed:?}");
    assert_eq!(
        plain,
        vec![(
            Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4665),
            DESC_REQ.to_vec()
        )]
    );
}

/// The answer to a sealed ask comes sealed from the obfuscation port, keyed
/// on the same stored `ServerUDPKey` in the server-to-client direction
/// (`ServerUDPSocket.cpp:70-92`): it opens and lands like a plain one.
#[tokio::test]
async fn the_sealed_answer_from_the_obfuscation_port_opens_under_the_stored_key() {
    let (engine, transport, challenges) = engine_under(REQUESTED, Ipv4Addr::new(203, 0, 113, 3));
    let server = Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4661);
    challenges.expect(server, 0x55AA_0007);
    engine
        .demux(
            keyed_stat_res(0x55AA_0007),
            Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4665),
        )
        .await;
    assert_eq!(transport.obfuscated.lock().unwrap().len(), 1, "sealed ask");

    let answer = encrypt_datagram_server(
        &desc_res_datagram(0xABCD_F0FF),
        KEY,
        ServerCryptDirection::FromServer,
        &DatagramNonce {
            marker_byte: 0x51,
            random_key: 0xBEEF,
            padding: Vec::new(),
        },
    );
    engine
        .demux(answer, Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, OBF_PORT))
        .await;

    let store = engine.capabilities.lock().unwrap();
    let display = &store.get(&server).expect("the 0x97 record").display;
    assert_eq!(display.name.as_deref(), Some("Lugdunum"));
}
