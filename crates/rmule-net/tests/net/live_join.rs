//! Live-network Kad join proof: drive one real `rmule_net::kad` node
//! against the public Kad network from a genuine `nodes.dat` and demand the
//! gold-standard observable — a counterparty answer (`ContactResponded`).
//!
//! Skipped silently when `RMULE_LIVE_KAD_NODES` is unset, so CI without
//! network access never sees it. Run it by hand:
//!
//! ```text
//! RMULE_LIVE_KAD_NODES=$HOME/.local/share/rmule/nodes.dat \
//!   cargo test -p rmule-net --test live_join -- --nocapture
//! ```
//!
//! `RMULE_LIVE_KAD_MODE` selects the seed shape:
//! - `merge` (default) — the shipped app's shape: the file's contacts
//!   enter the routing table via `MergeContacts` and the node's own join
//!   cadence must reach out. This is that cadence's regression anchor:
//!   without the not-joined hello cadence, a merge-seeded node sends nothing
//!   for 3 minutes and never emits `ContactResponded` at all.
//! - `dial` — the control: `Bootstrap` (`KADEMLIA2_BOOTSTRAP_REQ`) toward the
//!   same endpoints, the flow-H-proven join path. Separates "the seeds are
//!   dead" from "the merge path never reaches them".
//!
//! `RMULE_LIVE_KAD_SECS` (default 60) bounds the wait.

use std::time::Duration;

use rmule_kad::{KadCommand, KadEvent, KadId, KadNodeConfig, NodesDat, UserHash};
use rmule_net::kad::{KadNetConfig, spawn};

const ENV_NODES: &str = "RMULE_LIVE_KAD_NODES";
const ENV_MODE: &str = "RMULE_LIVE_KAD_MODE";
const ENV_SECS: &str = "RMULE_LIVE_KAD_SECS";

/// How many endpoints the `dial` control mode bootstraps toward. A handful is
/// plenty: the point is "are these seeds alive and answering us", not a sweep.
const DIAL_FANOUT: usize = 8;

#[tokio::test]
async fn a_nodes_dat_seeded_node_reaches_the_live_network() {
    let Ok(path) = std::env::var(ENV_NODES) else {
        eprintln!("skipping: {ENV_NODES} unset");
        return;
    };
    let mode = std::env::var(ENV_MODE).unwrap_or_else(|_| "merge".to_owned());
    let wait_secs: u64 = std::env::var(ENV_SECS)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);

    let bytes = std::fs::read(&path).expect("read the nodes.dat under test");
    let contacts = NodesDat::decode(&bytes)
        .expect("decode the nodes.dat under test")
        .into_contacts();
    assert!(
        !contacts.is_empty(),
        "the live proof needs a nodes.dat with at least one contact"
    );
    eprintln!(
        "live_join: {} contacts from {path}, mode={mode}",
        contacts.len()
    );

    let capture_dir = tempfile::tempdir().expect("capture dir");
    let mut handle = spawn(
        KadNetConfig {
            node: KadNodeConfig {
                id: KadId::from_bytes([0x37; KadId::BYTE_LEN]),
                tcp_port: 4662,
                // 0 = patched to the ephemeral bound port: never collides with a
                // running rmule/aMule holding 4672 on the same machine.
                udp_port: 0,
                user_hash: UserHash::from_bytes([0x37; 16]),
            },
            capture_dir: Some(capture_dir.path().to_path_buf()),
            nodes_dat_path: None,
            firewall_self_check: false,
            datagram_obfuscation: false,
            verify_keys: None,
            contact_admission: None,
        },
        "0.0.0.0:0".parse().unwrap(),
    )
    .await
    .expect("spawn the live Kad node");
    eprintln!("live_join: bound {}", handle.local_addr());

    match mode.as_str() {
        "merge" => {
            handle
                .command(KadCommand::MergeContacts {
                    contacts: contacts.clone(),
                })
                .await
                .expect("merge the file contacts");
        }
        "dial" => {
            for contact in contacts.iter().take(DIAL_FANOUT) {
                handle
                    .command(KadCommand::Bootstrap {
                        endpoint: contact.endpoint(),
                    })
                    .await
                    .expect("dial a bootstrap candidate");
            }
        }
        other => panic!("unknown {ENV_MODE}={other} (merge|dial)"),
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(wait_secs);
    let mut added = 0usize;
    let mut responded: Option<KadId> = None;
    while tokio::time::Instant::now() < deadline {
        let event = tokio::time::timeout_at(deadline, handle.next_event()).await;
        match event {
            Ok(Some(KadEvent::ContactAdded { .. })) => added += 1,
            Ok(Some(KadEvent::ContactResponded { id })) => {
                responded = Some(id);
                break;
            }
            Ok(Some(other)) => eprintln!("live_join: event {other:?}"),
            Ok(None) => panic!("driver ended early"),
            Err(_) => break,
        }
    }

    let summary = handle.shutdown().await.expect("driver shutdown");
    eprintln!(
        "live_join: mode={mode} contacts_added={added} responded={responded:?} \
         datagrams_out={} datagrams_in={}",
        summary.datagrams_out, summary.datagrams_in
    );
    assert!(
        responded.is_some(),
        "no counterparty Kad datagram answered us within {wait_secs}s \
         (mode={mode}, {} datagrams out, {} in) — the node did not join the live network",
        summary.datagrams_out,
        summary.datagrams_in
    );
}
