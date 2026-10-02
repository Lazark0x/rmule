//! The datagram capture tap records every in/out datagram with direction,
//! remote endpoint, and opcode meta (ADR-0022: capture is a first-class
//! library feature, not a debugging bolt-on).

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use rmule_kad::{KadCommand, KadEvent, KadId, KadNodeConfig, KadNodeEndpoint};
use rmule_net::kad::{KadNetConfig, spawn};

#[tokio::test]
async fn capture_records_datagram_frames_with_direction_and_opcode_meta() {
    let capture_root = tempfile::tempdir().expect("tempdir");
    let a_dir = capture_root.path().join("a");

    let mut a = spawn(
        KadNetConfig {
            node: KadNodeConfig {
                id: KadId::from_bytes([0xA1; 16]),
                tcp_port: 4662,
                udp_port: 0,
                user_hash: rmule_kad::UserHash::from_bytes([0xA1; 16]),
            },
            capture_dir: Some(a_dir.clone()),
            nodes_dat_path: None,
            firewall_self_check: false,
            datagram_obfuscation: false,
            verify_keys: None,
            contact_admission: None,
        },
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )
    .await
    .expect("node A binds");
    let b = spawn(
        KadNetConfig {
            node: KadNodeConfig {
                id: KadId::from_bytes([0xB1; 16]),
                tcp_port: 4662,
                udp_port: 0,
                user_hash: rmule_kad::UserHash::from_bytes([0xB1; 16]),
            },
            capture_dir: None,
            nodes_dat_path: None,
            firewall_self_check: false,
            datagram_obfuscation: false,
            verify_keys: None,
            contact_admission: None,
        },
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )
    .await
    .expect("node B binds");

    a.command(KadCommand::Bootstrap {
        endpoint: KadNodeEndpoint::new(Ipv4Addr::LOCALHOST, b.local_addr().port()),
    })
    .await
    .expect("driver accepts commands");
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if a.next_event().await.expect("driver alive")
                == (KadEvent::ContactResponded {
                    id: KadId::from_bytes([0xB1; 16]),
                })
            {
                return;
            }
        }
    })
    .await
    .expect("A converges on B");

    let b_addr = b.local_addr();
    a.shutdown().await.expect("clean shutdown");
    b.shutdown().await.expect("clean shutdown");

    // Finalized files exist; no .partial leftovers on a clean shutdown.
    assert!(a_dir.join("datagrams.bin").exists());
    assert!(a_dir.join("datagrams.toml").exists());
    assert!(a_dir.join("meta.toml").exists());
    assert!(!a_dir.join("datagrams.bin.partial").exists());

    // The frame meta records A's four-datagram exchange in order, with
    // direction, the remote endpoint, and decoded opcode meta.
    let frames: toml::Value =
        toml::from_str(&std::fs::read_to_string(a_dir.join("datagrams.toml")).expect("read toml"))
            .expect("valid toml");
    let frames = frames["frame"].as_array().expect("frame array");
    let meta: Vec<(&str, i64, &str)> = frames
        .iter()
        .map(|f| {
            (
                f["direction"].as_str().expect("direction"),
                f["opcode"].as_integer().expect("opcode"),
                f["remote"].as_str().expect("remote"),
            )
        })
        .collect();
    let b_remote = b_addr.to_string();
    assert_eq!(
        meta,
        vec![
            ("out", 0x01, b_remote.as_str()), // bootstrap req
            ("in", 0x09, b_remote.as_str()),  // bootstrap res
            ("out", 0x11, b_remote.as_str()), // hello probe
            ("in", 0x19, b_remote.as_str()),  // hello res
        ]
    );

    // The raw frames concatenate to exactly the wire bytes: length-prefixed,
    // starting with A's bootstrap request e4 01.
    let bin = std::fs::read(a_dir.join("datagrams.bin")).expect("read bin");
    let first_len = u32::from_le_bytes([bin[0], bin[1], bin[2], bin[3]]) as usize;
    assert_eq!(first_len, 2);
    assert_eq!(&bin[4..6], &[0xE4, 0x01]);
    let declared: usize = frames
        .iter()
        .map(|f| f["len"].as_integer().expect("len") as usize + 4)
        .sum();
    assert_eq!(bin.len(), declared, "bin holds exactly the declared frames");
}
