//! Kad traffic counted where the client-UDP demux meets the Kad node:
//! a hello sent to the one bound port, through the front's demux,
//! into a real node over the shared bind, and its answer back out — the
//! counters equal the bytes each side of the loopback saw. With obfuscation
//! on, both counts are the obfuscated sizes: the count is taken outside the
//! Kad crypt, on the wire.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use rmule_kad::{Kad2Message, Kad2NodeInfo, KadId, KadNodeConfig};
use rmule_net::ed2k::ClientUdpSocket;
use rmule_net::family::FamilySelection;
use rmule_net::kad::{KadTraffic, KadTrafficTotals};
use rmule_primitives::{
    ClientEncryptKey, DatagramNonce, Ipv4Endpoint, PeerEndpoint, UserHash, encrypt_datagram_client,
};
use tokio::sync::mpsc;

use super::{ClientUdpEngine, ClientUdpSend, SharedKadInlet};
use crate::adapters::RuntimeClientUdpTransport;
use crate::buddy_link::SharedBuddySlot;
use crate::diagnostics::DiagnosticsState;

const STEP: Duration = Duration::from_secs(5);
/// How long the counterparty listens past the first answer for any other.
const QUIET: Duration = Duration::from_millis(300);
const OUR_ID: [u8; 16] = [0x11; 16];

/// One hello through the demux and every answer back, with the node's
/// obfuscation `obfuscated`. Returns the hello's wire bytes, the answers'
/// wire bytes and the node's counters once they account for both.
async fn one_exchange(obfuscated: bool) -> (Vec<u8>, Vec<Vec<u8>>, KadTrafficTotals) {
    let socket = Arc::new(
        ClientUdpSocket::bind_with(0, FamilySelection::v4_only())
            .await
            .expect("a loopback client-UDP pair binds"),
    );
    let us = PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::LOCALHOST, socket.local_port()));
    let kad_inlet = SharedKadInlet::default();
    let (reply_tx, _reply_rx) = mpsc::channel::<ClientUdpSend>(16);
    let (engine, _inboxes) = ClientUdpEngine::new(
        RuntimeClientUdpTransport::new(Arc::clone(&socket)),
        None,
        SharedBuddySlot::default(),
        crate::firewalled::front::SharedFirewalledFront::default(),
        DiagnosticsState::default(),
        reply_tx,
        kad_inlet.clone(),
    );
    tokio::spawn(engine.run());

    let traffic = KadTraffic::default();
    let (inlet_tx, inlet_rx) = mpsc::channel(rmule_net::kad::KAD_INLET_CAPACITY);
    let _node = rmule_net::kad::spawn_over(
        rmule_net::kad::KadNetConfig {
            node: KadNodeConfig {
                id: KadId::from_bytes(OUR_ID),
                tcp_port: 4662,
                udp_port: 0,
                user_hash: UserHash::from_bytes([0x11; UserHash::BYTE_LEN]),
            },
            capture_dir: None,
            nodes_dat_path: None,
            firewall_self_check: false,
            // The production pairing: the keys ride inside the crypt header,
            // so the two arm together.
            datagram_obfuscation: obfuscated,
            verify_keys: obfuscated.then_some((0x005E_C2E7, Ipv4Addr::LOCALHOST)),
            contact_admission: None,
        },
        rmule_net::kad::KadInlet {
            datagrams: inlet_rx,
            socket: Arc::clone(&socket),
            traffic: traffic.clone(),
        },
    )
    .await
    .expect("the Kad node starts over the shared bind");
    *kad_inlet.lock().expect("kad inlet mutex") = Some(inlet_tx);

    let peer = ClientUdpSocket::bind_with(0, FamilySelection::v4_only())
        .await
        .expect("a counterparty socket binds");
    let hello = Kad2Message::HelloReq(Kad2NodeInfo {
        id: KadId::from_bytes([0xC1; 16]),
        tcp_port: 4662,
        version: 9,
        udp_port_tag: Some(peer.local_port()),
        misc_options: 0,
    })
    .encode()
    .encode();
    let wire = if obfuscated {
        encrypt_datagram_client(
            &hello,
            &ClientEncryptKey::KadNode {
                kad_id: &OUR_ID,
                receiver_verify_key: 0,
                sender_verify_key: 0,
            },
            &DatagramNonce {
                marker_byte: 0x5A,
                random_key: 0x1234,
                padding: vec![0; 4],
            },
        )
    } else {
        hello
    };
    peer.send_to_peer(us, &wire)
        .await
        .expect("the hello leaves");

    let mut answers = Vec::new();
    let (first, _) = tokio::time::timeout(STEP, peer.recv())
        .await
        .expect("the node answers the hello")
        .expect("receive succeeds");
    answers.push(first);
    while let Ok(Ok((more, _))) = tokio::time::timeout(QUIET, peer.recv()).await {
        answers.push(more);
    }
    // A send is counted once it returns, which may trail its arrival here.
    let totals = tokio::time::timeout(STEP, async {
        loop {
            let totals = traffic.totals();
            if totals.datagrams_out >= answers.len() as u64 {
                return totals;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the counters catch up with the loopback");
    (wire, answers, totals)
}

fn expected(hello: &[u8], answers: &[Vec<u8>]) -> KadTrafficTotals {
    KadTrafficTotals {
        datagrams_in: 1,
        bytes_in: hello.len() as u64,
        datagrams_out: answers.len() as u64,
        bytes_out: answers.iter().map(|a| a.len() as u64).sum(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn plaintext_kad_is_counted_both_ways_at_its_wire_size() {
    let (hello, answers, totals) = one_exchange(false).await;
    assert!(
        answers.iter().all(|a| a[0] == 0xE4 || a[0] == 0xE5),
        "a node without obfuscation answers in plaintext"
    );
    assert_eq!(totals, expected(&hello, &answers));
}

#[tokio::test(flavor = "multi_thread")]
async fn obfuscated_kad_is_counted_outside_the_crypt() {
    let (hello, answers, totals) = one_exchange(true).await;
    assert!(
        answers.iter().all(|a| a[0] != 0xE4 && a[0] != 0xE5),
        "the node obfuscates its answer to a v9 contact"
    );
    // Both directions count the obfuscated sizes — header, padding and
    // trailer included — not the Kad payload inside them.
    assert_eq!(totals, expected(&hello, &answers));
}
