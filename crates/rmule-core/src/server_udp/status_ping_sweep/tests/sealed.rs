//! The sweep's `0x96` through the seal: after an unanswered crypt-ping,
//! aMule's plain fallback leaves through `SendPacket` like every non-raw
//! datagram (`ServerList.cpp:335`, `ServerUDPSocket.cpp:366-374`), so it is
//! sealed when the server's row holds a key learned under our address — a
//! key saved by an earlier run included (`Server.cpp:300-307`).

use rmule_ed2k::ServerUdpFlags;
use rmule_primitives::{ServerCryptDirection, decrypt_datagram_server};

use super::super::super::tests::seal_over;
use super::*;
use crate::server_list::{ServerFigures, ServerUdpCrypt};

const KEY: u32 = 0x05A6_8835;
const OBF_PORT: u16 = 4675;

/// A row whose last answer, in an earlier run, left a key learned under
/// `key_ip` and advertised UDP obfuscation.
fn keyed_row(key_ip: Ipv4Addr) -> ManagedServer {
    let mut row = ManagedServer::listed(server("10.0.0.1", 4661));
    row.udp_crypt = Some(ServerUdpCrypt {
        obfuscation_udp_port: OBF_PORT,
        obfuscation_tcp_port: 4661,
        udp_key: KEY,
        key_ip: Some(key_ip),
    });
    row.figures = Some(ServerFigures {
        udp_flags: Some(ServerUdpFlags::from_bits(ServerUdpFlags::UDPOBFUSCATION)),
        ..ServerFigures::answered(1)
    });
    row
}

/// The fallback after a timed-out crypt-ping, toward a row whose key was
/// learned under `key_ip` while we hold 203.0.113.9: what went out plain
/// and what went out obfuscated after the crypt-ping.
async fn fallback_toward(
    key_ip: Ipv4Addr,
) -> (Vec<(Ipv4Endpoint, Vec<u8>)>, Vec<(Ipv4Endpoint, Vec<u8>)>) {
    let transport = Arc::new(scripted(vec![]));
    let crypt = crypt_arm();
    let facts = test_facts_rows(vec![keyed_row(key_ip)]).0;
    let sweep = StatusPingSweep {
        seal: seal_over(
            Arc::clone(&transport),
            crypt.policy.clone(),
            crypt.own.clone(),
            crate::server_capabilities::SharedServerCapabilities::default(),
            facts.clone(),
        ),
        facts,
        challenges: StatusChallenges::default(),
        entropy: fixed_entropy,
        first_contact_tick: Duration::from_millis(250),
        tick: Duration::from_secs(5),
        reask: Duration::from_secs(16_200),
        crypt,
        resolver: crate::name_resolver::FakeNameResolver::knowing(&[]),
    };
    let mut state = SweepState::default();

    sweep.ping_next(&mut state).await;
    tokio::time::advance(Duration::from_secs(20)).await;
    sweep.ping_next(&mut state).await;

    let plain = transport.sends.lock().unwrap().clone();
    let mut obfuscated = transport.obfuscated.lock().unwrap().clone();
    let crypt_ping = obfuscated.remove(0);
    assert_eq!(
        crypt_ping.0,
        Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, 1), 4673)
    );
    (plain, obfuscated)
}

#[tokio::test(start_paused = true)]
async fn the_fallback_ping_to_a_row_with_a_saved_key_is_sealed_to_its_obfuscation_port() {
    let (plain, sealed) = fallback_toward(Ipv4Addr::new(203, 0, 113, 9)).await;

    assert!(plain.is_empty(), "no plain 0x96: {plain:?}");
    assert_eq!(sealed.len(), 1);
    let (to, datagram) = &sealed[0];
    assert_eq!(*to, Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, 1), OBF_PORT));
    assert_eq!(
        decrypt_datagram_server(datagram, KEY, ServerCryptDirection::ToServer),
        Some(vec![0xE3, 0x96, 0xCD, 0xAB, 0xAA, 0x55])
    );
}

/// A key the server derived from an address we no longer hold keys nothing:
/// the fallback goes plain to standard port + 4.
#[tokio::test(start_paused = true)]
async fn the_fallback_ping_under_a_key_from_another_address_goes_plain() {
    let (plain, sealed) = fallback_toward(Ipv4Addr::new(198, 51, 100, 7)).await;

    assert!(sealed.is_empty(), "nothing sealed: {sealed:?}");
    assert_eq!(
        plain,
        vec![(
            Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, 1), 4665),
            vec![0xE3, 0x96, 0xCD, 0xAB, 0xAA, 0x55]
        )]
    );
}
