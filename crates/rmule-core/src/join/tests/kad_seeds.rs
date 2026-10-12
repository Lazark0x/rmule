//! The Kad-seed leg's routes driven through the whole sequence, which is where
//! their effect is observable: what rides the dispatched `EnableKad` command.
//! The warm restart, the default strand, the opt-in acquisition, and the two
//! failures that must not stop the join.

use super::*;

// --- nodes.dat fixtures: rmule's own v2 writer round-tripped through the
// reader, which is exactly the warm-restart path (deterministic tier, not
// an aMule capture) ---------------------------------------------------------

fn seed_contact(n: u8) -> rmule_kad::KadContact {
    rmule_kad::KadContact::new(
        KadId::from_bytes([n; KadId::BYTE_LEN]),
        // Routable and non-DNS: aMule's `IsGoodIPPort` + port-53 filters
        // drop anything else before it ever becomes a seed.
        rmule_kad::KadNodeEndpoint::new(Ipv4Addr::new(203, 0, 113, n), 4672),
        4662,
        8,
    )
}

fn nodes_dat_v2(count: u8) -> Vec<u8> {
    rmule_kad::NodesDat::encode_v2(&(1..=count).map(seed_contact).collect::<Vec<_>>())
}

fn kad_join(commands: &[CoreCommand]) -> &KadEnableConfig {
    match commands.iter().find_map(|c| match c {
        CoreCommand::EnableKad(config) => Some(config),
        _ => None,
    }) {
        Some(config) => config,
        None => panic!("no Kad join command dispatched: {commands:?}"),
    }
}

/// A persisted server list, so the only fetch a Kad test can observe is the
/// nodes.dat one.
fn store_with_a_server() -> crate::store::app_config::DurableAppConfig {
    seeded_store(&[ServerEndpoint::new("9.9.9.9", 4661).unwrap()])
}

/// The warm restart: the routing table the Kad driver persisted comes back
/// as merge-ready contacts on the join command, and nothing is acquired —
/// a saved table is not a cold start, even with the acquisition opted in.
#[tokio::test]
async fn a_persisted_nodes_dat_seeds_the_kad_join_and_suppresses_the_acquisition() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nodes.dat");
    std::fs::write(&path, nodes_dat_v2(3)).unwrap();
    let store = store_with_a_server();
    let fetcher = FakeFetcher::failing(FetchError::Timeout {
        url: "http://mirror".to_owned(),
    });
    let sink = RecordingSink::default();

    let outcome = run_join_sequence(
        &store,
        &fetcher,
        &opted_in(),
        &JoinConfig::default(),
        KadEnableConfig {
            nodes_dat_path: Some(path),
            ..kad_config()
        },
        own_id(),
        &sink,
    )
    .await
    .unwrap();

    assert_eq!(
        outcome.kad_seed,
        KadSeedOutcome::Persisted {
            contacts: 3,
            candidates: 0
        }
    );
    assert_eq!(fetcher.calls(), 0, "a warm restart acquires nothing");
    let commands = sink.commands();
    let joined = kad_join(&commands);
    assert_eq!(
        joined.contacts.len(),
        3,
        "the saved contacts ride the join command, ready to merge"
    );
    assert!(
        joined.bootstrap.is_empty(),
        "contacts carry their own Kad IDs — nothing to dial for one"
    );
}

/// The default cold start is aMule's: nothing saved, nothing fetched, and
/// Kad **still joins**. The empty-table node is what arms the ed2k→Kad
/// handoff, so refusing to start it would be the real regression.
#[tokio::test]
async fn a_cold_kad_start_strands_by_default_and_joins_anyway() {
    let store = store_with_a_server();
    let fetcher = FakeFetcher::failing(FetchError::Timeout {
        url: "http://mirror".to_owned(),
    });
    let sink = RecordingSink::default();

    let outcome = run_join_sequence(
        &store,
        &fetcher,
        &BootstrapConfig::default(),
        &JoinConfig::default(),
        kad_config(),
        own_id(),
        &sink,
    )
    .await
    .unwrap();

    assert_eq!(
        outcome.kad_seed,
        KadSeedOutcome::Stranded { read_error: None }
    );
    assert_eq!(
        fetcher.calls(),
        0,
        "the default switch is OFF: aMule never fetches nodes.dat unattended"
    );
    assert!(kad_join(&sink.commands()).contacts.is_empty());
}

/// The opt-in half (the `rmule` TUI's posture, ADR-0067 amendment): one
/// GET, decoded into merge-ready seeds.
#[tokio::test]
async fn the_opt_in_switch_acquires_contacts_for_a_cold_kad_start() {
    let store = store_with_a_server();
    let fetcher = FakeFetcher::serving(nodes_dat_v2(2));
    let sink = RecordingSink::default();

    let outcome = run_join_sequence(
        &store,
        &fetcher,
        &opted_in(),
        &JoinConfig::default(),
        kad_config(),
        own_id(),
        &sink,
    )
    .await
    .unwrap();

    assert_eq!(
        outcome.kad_seed,
        KadSeedOutcome::Acquired {
            contacts: 2,
            candidates: 0
        }
    );
    assert_eq!(fetcher.calls(), 1, "one-shot");
    assert_eq!(kad_join(&sink.commands()).contacts.len(), 2);
}

/// A persisted file that will not decode is *named*, not swallowed — and
/// it does not block the acquisition that would have run without it.
#[tokio::test]
async fn an_unusable_persisted_file_is_named_and_falls_through() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nodes.dat");
    // Nonzero leading word: a legacy version-0 file the reader refuses.
    std::fs::write(&path, 1u32.to_le_bytes()).unwrap();
    let kad = || KadEnableConfig {
        nodes_dat_path: Some(path.clone()),
        ..kad_config()
    };

    // Switch OFF: the reason survives into the outcome.
    let sink = RecordingSink::default();
    let outcome = run_join_sequence(
        &store_with_a_server(),
        &FakeFetcher::serving(nodes_dat_v2(2)),
        &BootstrapConfig::default(),
        &JoinConfig::default(),
        kad(),
        own_id(),
        &sink,
    )
    .await
    .unwrap();
    match outcome.kad_seed {
        KadSeedOutcome::Stranded {
            read_error: Some(reason),
        } => assert_eq!(reason, crate::SeedReadFault::TooOld),
        other => panic!("expected a named read failure, got {other:?}"),
    }

    // Switch ON: the same broken file is simply no seed, so the
    // acquisition runs exactly as it would on a bare cold start.
    let sink = RecordingSink::default();
    let outcome = run_join_sequence(
        &store_with_a_server(),
        &FakeFetcher::serving(nodes_dat_v2(2)),
        &opted_in(),
        &JoinConfig::default(),
        kad(),
        own_id(),
        &sink,
    )
    .await
    .unwrap();
    assert_eq!(
        outcome.kad_seed,
        KadSeedOutcome::Acquired {
            contacts: 2,
            candidates: 0
        }
    );
}

/// A failed acquisition is one-shot and non-fatal, exactly like the
/// server.met leg: the failure is reported and Kad joins stranded.
#[tokio::test]
async fn a_failed_kad_acquisition_still_joins() {
    let fetcher = FakeFetcher::failing(FetchError::Transport {
        url: "http://mirror/nodes.dat".to_owned(),
        detail: "connection refused".to_owned(),
    });
    let sink = RecordingSink::default();

    let outcome = run_join_sequence(
        &store_with_a_server(),
        &fetcher,
        &opted_in(),
        &JoinConfig::default(),
        kad_config(),
        own_id(),
        &sink,
    )
    .await
    .unwrap();

    assert!(
        matches!(outcome.kad_seed, KadSeedOutcome::AcquireFailed(_)),
        "the failure is reported, not swallowed: {:?}",
        outcome.kad_seed
    );
    assert_eq!(fetcher.calls(), 1, "one-shot: no retry on failure");
    assert!(kad_join(&sink.commands()).contacts.is_empty());
}
