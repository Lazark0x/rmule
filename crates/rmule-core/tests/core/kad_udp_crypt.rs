//! A production Core's Kad node speaks the Kad-UDP crypt: with
//! `CoreConfig::peer_crypt` set it obfuscates toward a crypt-era contact with
//! its verify key in the trailer, and it decrypts what a keyed counterparty
//! answers under that key — the lookup reply aMule sends under the requester's
//! `senderKey` (`KademliaUDPListener.cpp:682`) and the `0x62` a UDP firewall
//! helper keys on the `0xA7`'s verify key (`BaseClient.cpp:4008-4013`). With
//! the policy unset it stays plaintext (ADR-0046: one policy, off by default).
//!
//! The counterparty is a real `KadNode`, verify-key-armed and obfuscating,
//! driven by hand over a loopback socket so every byte the Core sends and
//! every byte it is answered with can be judged.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, DownloadCommand, KadEnableConfig, ObfuscationPolicy,
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

use crate::fixture::{dead_port, identity, kad_enable_config, stub_link};

/// The Core's persisted Kad UDP key — the seed its verify keys derive from.
const CORE_KAD_UDP_KEY: u32 = 0x0C0F_FEE5;
const HELPER_ID: KadId = KadId::from_bytes([0x5C; KadId::BYTE_LEN]);

/// The key the Core hands a counterparty at `ip`, derived as its node derives
/// it (aMule `CPrefs::GetUDPVerifyKey`, `Prefs.cpp:235-243`).
fn core_key_for(ip: Ipv4Addr) -> u32 {
    udp_verify_key(CORE_KAD_UDP_KEY, ip)
}

/// A verify-key-armed, obfuscating Kad node on a loopback socket.
struct Helper {
    node: KadNode,
    socket: UdpSocket,
}

impl Helper {
    async fn keyed() -> Self {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let mut node = KadNode::new(KadNodeConfig {
            id: HELPER_ID,
            tcp_port: 4662,
            udp_port: socket.local_addr().unwrap().port(),
            user_hash: UserHash::from_bytes([0x5C; UserHash::BYTE_LEN]),
        });
        node.enable_verify_keys(0x4E1F_0001, Ipv4Addr::LOCALHOST);
        node.enable_datagram_obfuscation(fixed_nonce);
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
        let (len, from) = timeout(Duration::from_secs(10), self.socket.recv_from(&mut buffer))
            .await
            .expect("the Core sent a Kad datagram within 10s")
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
fn opened_by_the_core(bytes: &[u8]) -> Option<Vec<u8>> {
    decrypt_datagram_client(
        bytes,
        &ClientDecryptKeys {
            receiver_verify_key: Some(core_key_for(Ipv4Addr::LOCALHOST)),
            ..ClientDecryptKeys::default()
        },
    )
    .map(|decrypted| decrypted.payload)
}

async fn core_with(peer_crypt: Option<ObfuscationPolicy>, contacts: Vec<KadContact>) -> Core {
    core_enabled(
        peer_crypt,
        CoreConfig::default(),
        KadEnableConfig {
            contacts,
            ..kad_enable_config()
        },
    )
    .await
}

/// A Core with `peer_crypt` as its one obfuscation policy, Kad enabled on
/// `config` with the Core's Kad UDP Key.
async fn core_enabled(
    peer_crypt: Option<ObfuscationPolicy>,
    core_config: CoreConfig,
    config: KadEnableConfig,
) -> Core {
    let core = Core::new(
        CoreConfig {
            peer_crypt,
            ..core_config
        },
        rmule_testkit::memory_store(),
    );
    core.send(CoreCommand::EnableKad(KadEnableConfig {
        kad_udp_key: CORE_KAD_UDP_KEY,
        ..config
    }))
    .await
    .unwrap();
    core
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
    let core = core_enabled(
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
    )
    .await;
    let output = tempfile::tempdir().unwrap();
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: stub_link("kad-crypt.bin", 4096, 0x39),
        source_hint: Some(ServerEndpoint::new("127.0.0.1", dead_port().await).unwrap()),
        credentials: identity().into(),
        output_path: output.path().join("kad-crypt.bin"),
    }))
    .await
    .unwrap();

    let mut keyed_lookup_replies = 0;
    let mut buffer = vec![0u8; 2048];
    let reached = timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                (core_addr, request) = helper.recv() => {
                    assert!(!is_plaintext_kad(&request), "the Core obfuscates toward a v8 contact");
                    for reply in helper.answer(core_addr, &request) {
                        if opened_by_the_core(&reply)
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
    let mut core = core_with(Some(ObfuscationPolicy::Requested), vec![helper.contact()]).await;
    // Learn where the Core's Kad socket is; answer nothing it asked.
    let (core_addr, _) = helper.recv().await;

    // The `0xA7` body the Core's node writes for a helper at loopback: intern
    // port, no distinct extern port, and its own verify key for our IP
    // (`BaseClient.cpp:3982-3986`). The helper keys both results on it.
    let mut request = core_addr.port().to_le_bytes().to_vec();
    request.extend_from_slice(&0u16.to_le_bytes());
    request.extend_from_slice(&core_key_for(Ipv4Addr::LOCALHOST).to_le_bytes());
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
        opened_by_the_core(&keyed_0x62).is_some(),
        "the helper's 0x62 is keyed on the 0xA7's key"
    );
    helper.socket.send_to(&keyed_0x62, core_addr).await.unwrap();

    assert!(
        heard_within(&mut core, Duration::from_secs(10)).await,
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
    let _core = core_with(None, vec![helper.contact()]).await;
    let (_, request) = helper.recv().await;
    assert!(is_plaintext_kad(&request));
}
