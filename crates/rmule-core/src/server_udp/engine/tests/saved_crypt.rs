//! A restart's receive path (ADR-0052's amendment): a server this run has
//! not heard is found by the obfuscation port its row saved, and its saved
//! `ServerUDPKey` keys a reply only under the public IPv4 it was learned
//! under.

use super::*;
use crate::server_list::{ManagedServer, ServerFigures, ServerListStore};

const OBF_PORT: u16 = 4675;

/// The facts seam a restarted core holds: a list whose one row kept the
/// crypt facts and UDP flags of an answer from an earlier run, and the level
/// seeded from it as the actor's prologue seeds it.
fn restarted_over(server: Ipv4Endpoint, key_ip: Ipv4Addr) -> ServerFacts {
    let store = crate::DurableAppConfig::new(
        crate::open_durable_store_in_memory().expect("the in-memory store opens"),
    );
    let row = ServerEndpoint::new(server.ip.to_string(), server.port).unwrap();
    store
        .merge_server(ManagedServer::listed(row.clone()))
        .unwrap();
    store
        .set_server_udp_crypt(&row, Some(saved_crypt(OBF_PORT, Some(key_ip))))
        .unwrap();
    store
        .edit_server_figures(&row, &mut |figures| {
            *figures = Some(ServerFigures {
                udp_flags: Some(ServerUdpFlags::from_bits(ServerUdpFlags::UDPOBFUSCATION)),
                ..ServerFigures::answered(1)
            });
        })
        .unwrap();
    let diagnostics = crate::diagnostics::DiagnosticsState::new();
    diagnostics.set_servers(store.servers().unwrap());
    ServerFacts::new(Arc::new(store), diagnostics, None)
}

/// Before any answer of this run, a crypt-ping reply from the saved
/// obfuscation port is the listed server's, keyed on its challenge.
#[tokio::test]
async fn a_restart_finds_a_crypt_ping_reply_by_the_saved_obfuscation_port() {
    let server = Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4661);
    let facts = restarted_over(server, Ipv4Addr::new(203, 0, 113, 9));
    let (engine, challenges, capabilities) = crypt_engine_over(facts, None);
    challenges.expect_crypt(server, 0x0BAD_F00D);

    engine
        .demux(
            encrypted_stat_res(0x0BAD_F00D, 900, 0x0BAD_F00D),
            Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, OBF_PORT),
        )
        .await;

    assert_eq!(
        capabilities.lock().unwrap().get(&server).map(|c| c.users),
        Some(900),
    );
    assert!(!challenges.crypt_outstanding(server));
}

/// The saved key decrypts a reply from the saved port while we hold the
/// address it was learned under, and keys nothing once we hold another.
#[tokio::test]
async fn a_restart_keys_on_the_saved_key_only_under_the_address_it_was_learned_under() {
    let server = Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, 4661);
    let learned_under = Ipv4Addr::new(203, 0, 113, 9);
    for (own, decrypts) in [
        (learned_under, true),
        (Ipv4Addr::new(198, 51, 100, 7), false),
    ] {
        let facts = restarted_over(server, learned_under);
        let (engine, challenges, capabilities) = crypt_engine_over(facts, Some(own));
        challenges.expect(server, 0x55AA_0042);

        engine
            .demux(
                encrypted_stat_res(0x55AA_0042, 1000, 0xABCD_1234),
                Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, OBF_PORT),
            )
            .await;

        let users = capabilities.lock().unwrap().get(&server).map(|c| c.users);
        assert_eq!(users.is_some(), decrypts, "public IPv4 {own}");
    }
}
