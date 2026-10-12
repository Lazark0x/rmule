//! A production Core's Kad node speaks the Kad-UDP crypt: with
//! `CoreSettings::obfuscation` set it obfuscates toward a crypt-era contact with
//! its verify key in the trailer, and it decrypts what a keyed counterparty
//! answers under that key — the lookup reply aMule sends under the requester's
//! `senderKey` (`KademliaUDPListener.cpp:682`) and the `0x62` a UDP firewall
//! helper keys on the `0xA7`'s verify key (`BaseClient.cpp:4008-4013`). With
//! the policy unset it stays plaintext (ADR-0046: one policy, off by default).
//!
//! The counterparty is a real `KadNode`, verify-key-armed and obfuscating,
//! driven by hand over a loopback socket so every byte the Core sends and
//! every byte it is answered with can be judged.

use rmule_kad::KadNodeStart;
use rmule_kad::KadObfuscation;
use rmule_testkit::HANG_GUARD;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use rmule_core::{
    AppConfigStore, Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand, KadEnableConfig,
    ObfuscationPolicy, Setting, TakesEffect,
};
use rmule_kad::opcode::KADEMLIA2_RES;
use rmule_kad::{
    KadCommand, KadContact, KadId, KadInstant, KadNode, KadNodeConfig, KadNodeEndpoint, KadOutput,
    udp_verify_key,
};
use rmule_primitives::{ClientDecryptKeys, ServerEndpoint, UserHash, decrypt_datagram_client};
use rmule_testkit::kad_node::fixed_nonce;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::fixture::{dead_port, kad_enable_config, stub_link};

const HELPER_ID: KadId = KadId::from_bytes([0x5C; KadId::BYTE_LEN]);

/// The key the Core whose persisted Kad UDP Key is `seed` hands a
/// counterparty at `ip`, derived as its node derives it (aMule
/// `CPrefs::GetUDPVerifyKey`, `Prefs.cpp:235-243`).
fn core_key_for(seed: u32, ip: Ipv4Addr) -> u32 {
    udp_verify_key(seed, ip)
}

/// A verify-key-armed, obfuscating Kad node on a loopback socket.
struct Helper {
    node: KadNode,
    socket: UdpSocket,
}

impl Helper {
    async fn keyed() -> Self {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let node = KadNode::new(
            KadNodeStart::new(
                KadNodeConfig {
                    id: HELPER_ID,
                    tcp_port: 4662,
                    udp_port: socket.local_addr().unwrap().port(),
                    user_hash: UserHash::from_bytes([0x5C; UserHash::BYTE_LEN]),
                },
                KadInstant::EPOCH,
            )
            .obfuscation(
                KadObfuscation::new(fixed_nonce).with_verify_keys(0x4E1F_0001, Ipv4Addr::LOCALHOST),
            ),
        );
        Self { node, socket }
    }

    /// How the Core knows the helper: a crypt-era (v8) contact with an earned
    /// ID, the nodes.dat "v1/v2-merge" shape `KadEnableConfig::contacts` takes.
    fn contact(&self) -> KadContact {
        let port = self.socket.local_addr().unwrap().port();
        KadContact::new(
            HELPER_ID,
            KadNodeEndpoint::new(Ipv4Addr::LOCALHOST, port),
            4662,
            8,
        )
    }

    async fn recv(&self) -> (SocketAddr, Vec<u8>) {
        let mut buffer = vec![0u8; 2048];
        let (len, from) = timeout(HANG_GUARD, self.socket.recv_from(&mut buffer))
            .await
            .expect("the Core sent a Kad datagram")
            .unwrap();
        buffer.truncate(len);
        (from, buffer)
    }

    /// Hand `bytes` to the node as if they arrived from `from`, and return
    /// every datagram it answers with — unsent, so the caller judges them.
    fn answer(&mut self, from: SocketAddr, bytes: &[u8]) -> Vec<Vec<u8>> {
        let SocketAddr::V4(from) = from else {
            panic!("the Core speaks Kad over IPv4");
        };
        let endpoint = KadNodeEndpoint::new(*from.ip(), from.port());
        self.node
            .handle_datagram(KadInstant::EPOCH, endpoint, bytes);
        rmule_primitives::session::drain(|| self.node.poll_output())
            .into_iter()
            .filter_map(|output| match output {
                KadOutput::Datagram { bytes, .. } => Some(bytes),
                KadOutput::Event(_) => None,
            })
            .collect()
    }
}

fn is_plaintext_kad(bytes: &[u8]) -> bool {
    matches!(bytes.first(), Some(0xE4 | 0xE5))
}

/// The plaintext of `bytes` if it decrypts under the receiver-verify family
/// keyed on the Core's own key for loopback — the family only a
/// verify-key-armed Core offers its receive path.
fn opened_by_the_core(seed: u32, bytes: &[u8]) -> Option<Vec<u8>> {
    decrypt_datagram_client(
        bytes,
        &ClientDecryptKeys {
            receiver_verify_key: Some(core_key_for(seed, Ipv4Addr::LOCALHOST)),
            ..ClientDecryptKeys::default()
        },
    )
    .map(|decrypted| decrypted.payload)
}

async fn core_with(
    peer_crypt: Option<ObfuscationPolicy>,
    contacts: Vec<KadContact>,
) -> (Core, u32) {
    core_enabled(
        peer_crypt,
        CoreConfig::default(),
        KadEnableConfig {
            contacts,
            ..kad_enable_config()
        },
        None,
    )
    .await
}

/// A Core with `peer_crypt` as its one obfuscation policy (`CoreSettings::obfuscation`), Kad enabled on
/// `config`, and the Kad UDP Key its store holds — the seed its verify keys
/// derive from; a download it starts lands in `download_dir`.
async fn core_enabled(
    peer_crypt: Option<ObfuscationPolicy>,
    core_config: CoreConfig,
    config: KadEnableConfig,
    download_dir: Option<&std::path::Path>,
) -> (Core, u32) {
    let store = rmule_testkit::memory_store();
    let seed = rmule_core::DurableAppConfig::new(std::sync::Arc::clone(&store))
        .ensure_kad_udp_key()
        .unwrap();
    let core = Core::builder(core_config, store)
        .settings(rmule_core::CoreSettings {
            obfuscation: peer_crypt,
            download_dir: download_dir.map(std::path::Path::to_path_buf),
            ..rmule_core::CoreSettings::default()
        })
        .build();
    core.send(CoreCommand::EnableKad(config)).await.unwrap();
    (core, seed)
}

/// Poll the snapshot until the node reports a received, decoded datagram
/// (aMule's `HasHadContact`) — `false` if it never does within `within`.
async fn heard_within(core: &mut Core, within: Duration) -> bool {
    timeout(within, async {
        loop {
            core.send(CoreCommand::DumpDiagnostics).await.unwrap();
            if let Some(CoreEvent::DiagnosticsSnapshot { snapshot }) = core.next_event().await
                && snapshot.kad.is_some_and(|kad| kad.contact_responded)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .is_ok()
}

#[tokio::test]
async fn a_crypt_armed_core_walks_on_a_lookup_reply_keyed_on_its_own_verify_key() {
    // A node only the helper knows of: the Core can reach it only by reading
    // the helper's `KADEMLIA2_RES`.
    let far = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let mut helper = Helper::keyed().await;
    helper.node.handle_command(
        KadInstant::EPOCH,
        KadCommand::MergeContacts {
            contacts: vec![
                KadContact::new(
                    KadId::from_bytes([0x0B; KadId::BYTE_LEN]),
                    KadNodeEndpoint::new(Ipv4Addr::LOCALHOST, far.local_addr().unwrap().port()),
                    4662,
                    8,
                )
                // Verified, as a served row must be once any verified one exists.
                .into_verified(),
            ],
        },
    );
    // A routing walk — a download's Kad source search — walks on to every
    // closer row a reply names. (The self-check's UDP helper lookup would
    // hand its rows to the tester instead.)
    let output = tempfile::tempdir().unwrap();
    let (core, seed) = core_enabled(
        Some(ObfuscationPolicy::Requested),
        CoreConfig {
            kad_sweep_interval: Duration::from_millis(100),
            ..CoreConfig::default()
        },
        KadEnableConfig {
            contacts: vec![helper.contact()],
            assume_open_reachability: true,
            ..kad_enable_config()
        },
        Some(output.path()),
    )
    .await;
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: stub_link("kad-crypt.bin", 4096, 0x39),
        source_hint: Some(ServerEndpoint::new("127.0.0.1", dead_port().await).unwrap()),
        name: rmule_testkit::file_name("kad-crypt.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
    }))
    .await
    .unwrap();

    let mut keyed_lookup_replies = 0;
    let mut buffer = vec![0u8; 2048];
    let reached = timeout(HANG_GUARD, async {
        loop {
            tokio::select! {
                (core_addr, request) = helper.recv() => {
                    assert!(!is_plaintext_kad(&request), "the Core obfuscates toward a v8 contact");
                    for reply in helper.answer(core_addr, &request) {
                        if opened_by_the_core(seed, &reply)
                            .is_some_and(|plain| plain.get(1) == Some(&KADEMLIA2_RES))
                        {
                            keyed_lookup_replies += 1;
                        }
                        helper.socket.send_to(&reply, core_addr).await.unwrap();
                    }
                }
                received = far.recv_from(&mut buffer) => {
                    received.unwrap();
                    return;
                }
            }
        }
    })
    .await;

    assert!(
        reached.is_ok(),
        "the Core walked on to the node the helper's lookup reply named"
    );
    assert!(
        keyed_lookup_replies > 0,
        "the reply that named it rode the receiver-verify family keyed on the Core's own key \
         (aMule answers a lookup under the requester's senderKey, KademliaUDPListener.cpp:682)"
    );
}

#[tokio::test]
async fn a_crypt_armed_core_reads_a_0x62_keyed_on_the_0xa7_verify_key() {
    let mut helper = Helper::keyed().await;
    let (mut core, seed) =
        core_with(Some(ObfuscationPolicy::Requested), vec![helper.contact()]).await;
    // Learn where the Core's Kad socket is; answer nothing it asked.
    let (core_addr, _) = helper.recv().await;

    // The `0xA7` body the Core's node writes for a helper at loopback: intern
    // port, no distinct extern port, and its own verify key for our IP
    // (`BaseClient.cpp:3982-3986`). The helper keys both results on it.
    let mut request = core_addr.port().to_le_bytes().to_vec();
    request.extend_from_slice(&0u16.to_le_bytes());
    request.extend_from_slice(&core_key_for(seed, Ipv4Addr::LOCALHOST).to_le_bytes());
    helper
        .node
        .consume_udp_firewall_request(Ipv4Addr::LOCALHOST, &request, false);
    let keyed_0x62 = rmule_primitives::session::drain(|| helper.node.poll_output())
        .into_iter()
        .find_map(|output| match output {
            KadOutput::Datagram { bytes, .. } => Some(bytes),
            KadOutput::Event(_) => None,
        })
        .expect("the helper answers the request");
    assert!(
        opened_by_the_core(seed, &keyed_0x62).is_some(),
        "the helper's 0x62 is keyed on the 0xA7's key"
    );
    helper.socket.send_to(&keyed_0x62, core_addr).await.unwrap();

    assert!(
        heard_within(&mut core, HANG_GUARD).await,
        "the Core decrypted the keyed 0x62 — the only datagram it was sent"
    );
}

#[tokio::test]
async fn by_default_a_core_speaks_kad_in_the_clear() {
    // ADR-0046's policy surface: one obfuscation policy across stream and
    // datagram, unset by default — so a default Core greets even a crypt-era
    // contact in plaintext, as aMule does with `IsClientCryptLayerSupported()`
    // off (`MuleUDPSocket.cpp:282-284`).
    let helper = Helper::keyed().await;
    let (_core, _) = core_with(None, vec![helper.contact()]).await;
    let (_, request) = helper.recv().await;
    assert!(is_plaintext_kad(&request));
}

/// The policy changes live (ADR-0046): a Core started plaintext and set to
/// `Requested` through its settings handle has its running Kad node re-armed,
/// so the lookups it keeps sending a crypt-era contact turn obfuscated with no
/// restart — and set off again, they turn plaintext.
#[tokio::test]
async fn a_live_policy_change_re_arms_the_running_kad_node_both_ways() {
    let mut helper = Helper::keyed().await;
    // A download's Kad source search re-asks every sweep, so the Core keeps
    // talking to the helper while the policy moves under it.
    let output = tempfile::tempdir().unwrap();
    let (core, _) = core_enabled(
        None,
        CoreConfig {
            kad_sweep_interval: Duration::from_millis(100),
            ..CoreConfig::default()
        },
        KadEnableConfig {
            contacts: vec![helper.contact()],
            assume_open_reachability: true,
            ..kad_enable_config()
        },
        Some(output.path()),
    )
    .await;
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: stub_link("kad-live-crypt.bin", 4096, 0x3A),
        source_hint: Some(ServerEndpoint::new("127.0.0.1", dead_port().await).unwrap()),
        name: rmule_testkit::file_name("kad-live-crypt.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
    }))
    .await
    .unwrap();
    // Answer everything, and hand back the first request that is (or is
    // not) obfuscated.
    let mut next_where = async |obfuscated: bool| {
        timeout(HANG_GUARD, async {
            loop {
                let (core_addr, request) = helper.recv().await;
                for reply in helper.answer(core_addr, &request) {
                    helper.socket.send_to(&reply, core_addr).await.unwrap();
                }
                if is_plaintext_kad(&request) != obfuscated {
                    return request;
                }
            }
        })
        .await
        .is_ok()
    };

    assert!(next_where(false).await, "the Core starts in the clear");
    assert_eq!(
        core.settings()
            .set(Setting::Obfuscation(Some(ObfuscationPolicy::Requested))),
        Ok(TakesEffect::Now)
    );
    assert!(
        next_where(true).await,
        "re-armed, the running node obfuscates toward the v8 contact"
    );
    assert_eq!(
        core.settings().set(Setting::Obfuscation(None)),
        Ok(TakesEffect::Now)
    );
    assert!(
        next_where(false).await,
        "disarmed, the running node speaks in the clear again"
    );
}
