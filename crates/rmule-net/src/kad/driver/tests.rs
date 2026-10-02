//! The consecutive-error budget on the driver's transport arm:
//! a permanently failing transport must end the run within the budget,
//! carrying the typed error and still running the clean-shutdown path, while
//! a transport that recovers before the budget trips must not be ended at
//! all.

use std::net::Ipv4Addr;

use rmule_kad::{KadContact, KadId, KadNodeEndpoint};
use rmule_primitives::UserHash;
use tokio::sync::{mpsc, oneshot};

use super::*;
use crate::family::{RECEIVE_ERROR_BACKOFF, RECEIVE_ERROR_BUDGET};
use crate::kad::transport::ScriptedTransport;

/// A node identity fixture: all-zero, so [`verified_contact`]'s single-bit
/// IDs each land in a distinct k-bucket (bucket index == the one set bit).
fn some_node_config() -> KadNodeConfig {
    KadNodeConfig {
        id: KadId::from_bytes([0u8; KadId::BYTE_LEN]),
        tcp_port: 4662,
        udp_port: 4672,
        user_hash: UserHash::from_bytes([0x42; UserHash::BYTE_LEN]),
    }
}

/// A verified routing contact whose ID has exactly one bit set, at
/// `bit_index`. Against [`some_node_config`]'s all-zero ID, the XOR distance's
/// highest set bit — and so the k-bucket index — is `bit_index` itself, so
/// distinct indices never collide in the same (capacity-limited) bucket the
/// way same-bucket contacts would.
fn verified_contact(bit_index: usize) -> KadContact {
    let mut id = [0u8; KadId::BYTE_LEN];
    id[bit_index / 8] = 1 << (bit_index % 8);
    KadContact::new(
        KadId::from_bytes(id),
        KadNodeEndpoint::new(
            Ipv4Addr::new(45, 55, u8::try_from(bit_index + 1).unwrap(), 2),
            4672,
        ),
        4662,
        8,
    )
    .into_verified()
}

/// A `run_driver` invocation wired with plain channels — no [`KadNetHandle`]
/// needed, since these tests read the task's own `Result` directly rather
/// than through [`KadNetHandle::shutdown`], which would race a requested
/// stop against the budget this suite is exercising. The returned
/// `shutdown_tx` must be kept alive (bound, not dropped) for the run's
/// whole life: a dropped sender resolves the shutdown arm too,
/// which would end the driver before the budget under test ever trips.
fn harness(
    transport: KadTransport,
    nodes_dat_path: Option<std::path::PathBuf>,
) -> (
    mpsc::Sender<KadCommand>,
    oneshot::Sender<()>,
    impl std::future::Future<Output = Result<KadNetSummary, KadNetError>>,
) {
    let (command_tx, command_rx) = mpsc::channel(64);
    let (event_tx, _event_rx) = mpsc::channel(1024);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let run = run_driver(
        transport,
        some_node_config(),
        command_rx,
        event_tx,
        shutdown_rx,
        RunRecord {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            capture: None,
            nodes_dat_path,
        },
        NodeArming::default(),
    );
    (command_tx, shutdown_tx, run)
}

#[tokio::test]
async fn a_transport_that_fails_forever_ends_the_driver_with_the_typed_error_and_persists_nodes_dat()
 {
    let dir = tempfile::tempdir().expect("tempdir");
    let nodes_dat_path = dir.path().join("nodes.dat");

    let transport = KadTransport::Scripted(ScriptedTransport::new(vec![Err(
        std::io::ErrorKind::ConnectionReset,
    )]));
    let (command_tx, _shutdown_tx, run) = harness(transport, Some(nodes_dat_path.clone()));

    // Merged before `run_driver` ever polls: `commands.recv()` is checked
    // before `transport.recv()` in the driver's biased select, so this is
    // in the routing table on the very first iteration — proving the
    // clean-shutdown persist below survives a budget-ended run, not merely
    // a graceful one.
    let contacts: Vec<KadContact> = (0..25).map(verified_contact).collect();
    command_tx
        .try_send(KadCommand::MergeContacts { contacts })
        .expect("the command queues ahead of the first poll");

    let outcome = tokio::time::timeout(std::time::Duration::from_secs(2), run)
        .await
        .expect(
            "a permanently failing transport must end the driver within the \
             budget, well under the timeout",
        );

    let error = outcome.expect_err("a permanently failing transport must end the driver");
    match error {
        KadNetError::TransportFailing { kind, consecutive } => {
            assert_eq!(kind, std::io::ErrorKind::ConnectionReset);
            assert_eq!(consecutive, RECEIVE_ERROR_BUDGET);
        }
        other => panic!("expected TransportFailing, got {other:?}"),
    }

    assert!(
        nodes_dat_path.exists(),
        "the routing table must survive a budget-ended run, not only a graceful one"
    );
}

#[tokio::test]
async fn a_receive_between_errors_resets_the_budget_and_the_driver_keeps_running() {
    // `RECEIVE_ERROR_BUDGET - 1` errors, then a receive, then (since a
    // scripted transport repeats its last entry) receives forever: the
    // budget must never trip as long as one lands before it would.
    let script: Vec<Result<(), std::io::ErrorKind>> = (0..RECEIVE_ERROR_BUDGET - 1)
        .map(|_| Err(std::io::ErrorKind::Other))
        .chain(std::iter::once(Ok(())))
        .collect();
    let transport = KadTransport::Scripted(ScriptedTransport::new(script));
    let (_command_tx, _shutdown_tx, run) = harness(transport, None);

    // Generous but bounded: the whole error run backs off at most
    // `RECEIVE_ERROR_BUDGET - 1` times before the resetting receive lands.
    let bound = RECEIVE_ERROR_BACKOFF * RECEIVE_ERROR_BUDGET * 4;
    let outcome = tokio::time::timeout(bound, run).await;

    assert!(
        outcome.is_err(),
        "a receive between two error runs must reset the budget, not exhaust it \
         — the driver should still be running when the bound elapses"
    );
}
