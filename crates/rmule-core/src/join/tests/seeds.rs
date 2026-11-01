//! ADR-0120 through the whole sequence: a cold start rests on the seeds, and a
//! fetched list adds to them and never replaces them.

use rmule_bootstrap::{ListOddity, Seeds, ServerMetPipelineError};
use rmule_ed2k::ServerPriority;

use super::kad_seeds::nodes_dat_v2;
use super::*;

const SEED_SERVER: &str = "192.0.2.1";

fn seeds() -> Seeds {
    Seeds::parse("server 192.0.2.1:4661\nkad 198.51.100.1:4672\n").expect("documentation seeds")
}

fn seeded() -> BootstrapConfig {
    BootstrapConfig {
        seeds: seeds(),
        auto_fetch_nodes_dat: true,
        ..BootstrapConfig::default()
    }
}

fn no_store() -> DurableAppConfig {
    DurableAppConfig::new(rmule_testkit::memory_store())
}

fn unreachable_mirror() -> FakeFetcher {
    FakeFetcher::failing(FetchError::Transport {
        url: "http://mirror".to_owned(),
        detail: "the path dropped it".to_owned(),
    })
}

fn seed_endpoint() -> ServerEndpoint {
    ServerEndpoint::new(SEED_SERVER, 4661).unwrap()
}

/// A valid server.met of `rows`, each `(address, port, preference)`.
fn met(rows: &[(Ipv4Addr, u16, Option<u32>)]) -> Vec<u8> {
    let mut bytes = vec![0xE0u8];
    bytes.extend_from_slice(&u32::try_from(rows.len()).unwrap().to_le_bytes());
    for (ip, port, preference) in rows {
        bytes.extend_from_slice(&Ipv4Endpoint::new(*ip, *port).encode());
        let tags: Vec<_> = preference
            .iter()
            .map(|preference| Tag::new(TagName::compact_id(0x0E), TagValue::U32(*preference)))
            .collect();
        bytes.extend_from_slice(&u32::try_from(tags.len()).unwrap().to_le_bytes());
        for tag in &tags {
            bytes.extend(tag.encode());
        }
    }
    bytes
}

async fn join(
    store: &DurableAppConfig,
    fetcher: &FakeFetcher,
    bootstrap: &BootstrapConfig,
    kad: KadEnableConfig,
) -> (JoinOutcome, Vec<CoreCommand>) {
    let sink = RecordingSink::default();
    let outcome = run_join_sequence(
        store,
        fetcher,
        bootstrap,
        &JoinConfig::default(),
        kad,
        own_id(),
        &sink,
    )
    .await
    .unwrap();
    (outcome, sink.commands())
}

fn kad_join(commands: &[CoreCommand]) -> &KadEnableConfig {
    commands
        .iter()
        .find_map(|command| match command {
            CoreCommand::EnableKad(config) => Some(config),
            _ => None,
        })
        .expect("a Kad join")
}

/// The ticket's first half: every fetch fails and both networks still have
/// somewhere to go.
#[tokio::test]
async fn a_cold_start_with_every_fetch_failing_joins_from_the_seeds() {
    let store = no_store();
    let fetcher = unreachable_mirror();

    let (outcome, commands) = join(&store, &fetcher, &seeded(), kad_config()).await;

    assert!(matches!(outcome.first_run, FirstRunFetch::Failed(_)));
    assert_eq!(outcome.servers, [seed_endpoint()]);
    assert_eq!(ed2k_servers(&commands), [seed_endpoint()]);
    assert_eq!(
        fetcher.calls(),
        2,
        "a server.met and a nodes.dat, each once"
    );
    assert_eq!(
        kad_join(&commands).bootstrap,
        ["198.51.100.1:4672"
            .parse::<std::net::SocketAddrV4>()
            .unwrap()]
    );
    assert!(matches!(
        outcome.kad_seed,
        KadSeedOutcome::Embedded {
            seeds: 1,
            fetched: 0,
            fetch_failed: Some(_)
        }
    ));
}

/// The ticket's second half: a list that passes for real adds its rows, and
/// the seed keeps its place and its priority under a row naming it `Low`.
#[tokio::test]
async fn a_forged_list_lands_beside_the_seeds_and_moves_none() {
    let store = no_store();
    let forged = FakeFetcher::serving(met(&[
        (Ipv4Addr::new(192, 0, 2, 1), 4661, Some(2)),
        (Ipv4Addr::new(203, 0, 113, 66), 4661, None),
    ]));

    let (outcome, commands) = join(
        &store,
        &forged,
        &BootstrapConfig {
            auto_fetch_nodes_dat: false,
            ..seeded()
        },
        kad_config(),
    )
    .await;

    assert!(matches!(
        outcome.first_run,
        FirstRunFetch::Installed { added: 1 }
    ));
    let listed = store.servers().unwrap();
    let seed = listed
        .iter()
        .find(|row| row.endpoint == seed_endpoint())
        .expect("the seed stays listed");
    assert_eq!(seed.priority, ServerPriority::High);
    assert_eq!(listed.len(), 2, "the forged row sits beside it");
    assert!(ed2k_servers(&commands).contains(&seed_endpoint()));
}

/// An odd list is the failed fetch of a forger who was not careful: none of it
/// lands, and the list is the seeds.
#[tokio::test]
async fn an_odd_list_leaves_only_the_seeds() {
    let store = no_store();
    let rows: Vec<_> = (1..=9)
        .map(|host| (Ipv4Addr::new(203, 0, 113, host), 4661, None))
        .collect();
    let forged = FakeFetcher::serving(met(&rows));

    let (outcome, _) = join(&store, &forged, &seeded(), kad_config()).await;

    assert_eq!(
        outcome.first_run,
        FirstRunFetch::Failed(ServerMetPipelineError::Odd(ListOddity::OneNetwork {
            in_network: 9,
            usable: 9
        }))
    );
    assert_eq!(outcome.servers, [seed_endpoint()]);
}

/// A forged nodes.dat sets every contact verified. Nothing of it reaches the
/// routing table: its addresses dial, after the seed.
#[tokio::test]
async fn a_fetched_nodes_dat_dials_behind_the_seeds_and_enters_no_table() {
    let store = seeded_store(&[ServerEndpoint::new("9.9.9.9", 4661).unwrap()]);
    let fetcher = FakeFetcher::serving(nodes_dat_v2(2));

    let (outcome, commands) = join(&store, &fetcher, &seeded(), kad_config()).await;

    assert_eq!(
        outcome.kad_seed,
        KadSeedOutcome::Embedded {
            seeds: 1,
            fetched: 2,
            fetch_failed: None
        }
    );
    let kad = kad_join(&commands);
    assert!(
        kad.contacts.is_empty(),
        "a fetched contact must answer first"
    );
    assert_eq!(
        kad.bootstrap[0],
        "198.51.100.1:4672"
            .parse::<std::net::SocketAddrV4>()
            .unwrap(),
        "the seed dials first"
    );
    assert_eq!(kad.bootstrap.len(), 3);
}

/// A warm start reads neither seeds nor mirror: a seed the operator removed
/// stays removed.
#[tokio::test]
async fn a_warm_start_lists_no_seed() {
    let kept = ServerEndpoint::new("9.9.9.9", 4661).unwrap();
    let store = seeded_store(std::slice::from_ref(&kept));
    let fetcher = unreachable_mirror();

    let (outcome, _) = join(
        &store,
        &fetcher,
        &BootstrapConfig {
            auto_fetch_nodes_dat: false,
            ..seeded()
        },
        kad_config(),
    )
    .await;

    assert_eq!(outcome.first_run, FirstRunFetch::Skipped);
    assert_eq!(outcome.servers, [kept]);
    assert_eq!(fetcher.calls(), 0);
}

/// The fetch switch is about fetching: with it off the seeds still list, and
/// nobody is asked.
#[tokio::test]
async fn the_seeds_list_with_the_fetch_switch_off() {
    let store = no_store();
    let fetcher = unreachable_mirror();

    let (outcome, _) = join(
        &store,
        &fetcher,
        &BootstrapConfig {
            auto_fetch_server_met: false,
            auto_fetch_nodes_dat: false,
            ..seeded()
        },
        kad_config(),
    )
    .await;

    assert_eq!(outcome.first_run, FirstRunFetch::Skipped);
    assert_eq!(outcome.servers, [seed_endpoint()]);
    assert_eq!(fetcher.calls(), 0);
}

/// An empty seed list changes nothing: a failed fetch leaves an empty list, and
/// no outcome claims a seed.
#[tokio::test]
async fn no_seeds_and_a_failed_fetch_is_an_empty_list() {
    let store = no_store();

    let (outcome, _) = join(
        &store,
        &unreachable_mirror(),
        &BootstrapConfig {
            auto_fetch_nodes_dat: true,
            ..BootstrapConfig::default()
        },
        kad_config(),
    )
    .await;

    assert!(matches!(outcome.first_run, FirstRunFetch::Failed(_)));
    assert!(outcome.servers.is_empty());
    assert!(matches!(outcome.kad_seed, KadSeedOutcome::AcquireFailed(_)));
}
