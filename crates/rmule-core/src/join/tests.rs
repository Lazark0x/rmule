//! The Join Sequence asserted end to end against a recording command sink: the
//! amuled cold start, the returning user, each network switch on its own, and
//! the one-shot posture a failed server.met fetch keeps. The fixtures are
//! deterministic canned bytes, never an aMule capture.

mod kad_seeds;

use std::net::Ipv4Addr;
use std::sync::Mutex;

use rmule_bootstrap::FetchError;
use rmule_primitives::{Ed2kText, Ipv4Endpoint, Tag, TagName, TagValue};

use crate::server_list::ManagedServer;
use crate::store::app_config::DurableAppConfig;
use crate::{KadEnableConfig, KadId};

use super::*;

// --- a canned-bytes server.met the first-run fetch parses (deterministic
// fixture, not an aMule capture) --------------------------------------------

fn met_one(ip: Ipv4Addr, port: u16, name: &str) -> Vec<u8> {
    let name_tag = Tag::new(
        TagName::compact_id(0x01),
        TagValue::String(Ed2kText::from_utf8(name)),
    );
    let mut bytes = vec![0xE0u8];
    bytes.extend_from_slice(&1u32.to_le_bytes()); // one row
    bytes.extend_from_slice(&Ipv4Endpoint::new(ip, port).encode());
    bytes.extend_from_slice(&1u32.to_le_bytes()); // one tag
    bytes.extend(name_tag.encode());
    bytes
}

// --- the injected Fetcher: canned bytes, a counted call, a "must not be
// called" guard for the skip cases ------------------------------------------

struct FakeFetcher {
    result: Result<Vec<u8>, FetchError>,
    calls: Mutex<usize>,
}

impl FakeFetcher {
    fn serving(bytes: Vec<u8>) -> Self {
        Self {
            result: Ok(bytes),
            calls: Mutex::new(0),
        }
    }
    fn failing(error: FetchError) -> Self {
        Self {
            result: Err(error),
            calls: Mutex::new(0),
        }
    }
    fn calls(&self) -> usize {
        *self.calls.lock().unwrap()
    }
}

impl Fetcher for FakeFetcher {
    fn get(
        &self,
        _url: &str,
        _max_bytes: usize,
    ) -> impl Future<Output = Result<Vec<u8>, FetchError>> + Send {
        *self.calls.lock().unwrap() += 1;
        let result = self.result.clone();
        async move { result }
    }
}

// --- the recording sink: captures the exact join commands and their order --

#[derive(Default)]
struct RecordingSink {
    commands: Mutex<Vec<CoreCommand>>,
}

impl RecordingSink {
    fn commands(&self) -> Vec<CoreCommand> {
        self.commands.lock().unwrap().clone()
    }
}

impl JoinCommandSink for RecordingSink {
    fn dispatch(&self, command: CoreCommand) -> impl Future<Output = Result<(), CoreError>> + Send {
        self.commands.lock().unwrap().push(command);
        async { Ok(()) }
    }
}

/// The node's Kad ID the seeds are resolved about.
fn own_id() -> KadId {
    KadId::from_bytes([0x11; KadId::BYTE_LEN])
}

fn kad_config() -> KadEnableConfig {
    KadEnableConfig {
        bootstrap: Vec::new(),
        contacts: Vec::new(),
        nodes_dat_path: None,
        assume_open_reachability: false,
        kad_capture_dir: None,
        kad_shutdown: None,
    }
}

fn seeded_store(servers: &[ServerEndpoint]) -> DurableAppConfig {
    let store = DurableAppConfig::new(rmule_testkit::memory_store());
    for server in servers {
        store
            .merge_server(ManagedServer::listed(server.clone()))
            .unwrap();
    }
    store
}

fn opted_in() -> BootstrapConfig {
    BootstrapConfig {
        auto_fetch_nodes_dat: true,
        ..BootstrapConfig::default()
    }
}

/// The rows the eD2k join handed core, in order.
fn ed2k_rows(commands: &[CoreCommand]) -> Vec<&ManagedServer> {
    commands
        .iter()
        .filter_map(|c| match c {
            CoreCommand::ServerList(ServerListCommand::AddServer { server }) => Some(server),
            _ => None,
        })
        .collect()
}

fn ed2k_servers(commands: &[CoreCommand]) -> Vec<ServerEndpoint> {
    ed2k_rows(commands)
        .into_iter()
        .map(|row| row.endpoint.clone())
        .collect()
}

/// The amuled cold start: empty list, both networks default ON, switch ON.
/// The sequence fetches, persists, then dispatches BOTH joins — the eD2k
/// join carrying the freshly acquired server, the Kad join following.
#[tokio::test]
async fn cold_start_fetches_persists_and_joins_both_networks() {
    let store = DurableAppConfig::new(rmule_testkit::memory_store());
    let acquired = ServerEndpoint::new("1.2.3.4", 4661).unwrap();
    let fetcher = FakeFetcher::serving(met_one(Ipv4Addr::new(1, 2, 3, 4), 4661, "Acquired"));
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

    assert_eq!(outcome.first_run, FirstRunFetch::Installed { added: 1 });
    assert_eq!(outcome.servers, vec![acquired.clone()]);
    assert_eq!(fetcher.calls(), 1, "one-shot first-run fetch");
    // The fetch persisted before the joins, carrying the row's metadata —
    // a cold start never lands a nameless endpoint (ADR-0080).
    let persisted = store.servers().unwrap();
    assert_eq!(persisted.len(), 1);
    assert_eq!(persisted[0].endpoint, acquired);
    assert_eq!(persisted[0].name.to_display_string(), "Acquired");

    // Sequence determinism: eD2k join first (the acquired row, named, through
    // core's one list writer), Kad join second — both present, in order.
    let commands = sink.commands();
    assert_eq!(commands.len(), 2);
    assert_eq!(ed2k_servers(&commands[..1]), vec![acquired]);
    assert_eq!(ed2k_rows(&commands)[0].name.to_display_string(), "Acquired");
    assert!(matches!(commands[1], CoreCommand::EnableKad(_)));
}

/// A returning user (a persisted list) is not a cold start: the fetch is
/// skipped, the persisted list is joined verbatim, and both networks still
/// join.
#[tokio::test]
async fn returning_user_skips_fetch_and_joins_persisted_list() {
    let persisted = ServerEndpoint::new("9.9.9.9", 4661).unwrap();
    let store = seeded_store(std::slice::from_ref(&persisted));
    // A fetcher that must never be called: a non-empty list is no first run.
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

    assert_eq!(outcome.first_run, FirstRunFetch::Skipped);
    assert_eq!(
        fetcher.calls(),
        0,
        "a persisted list must not trigger a fetch"
    );
    assert_eq!(outcome.servers, vec![persisted.clone()]);
    assert_eq!(ed2k_servers(&sink.commands()), vec![persisted]);
}

/// Each network switch is independent: disabling Kad joins only eD2k (and
/// still first-run-fetches, since eD2k is on); disabling eD2k joins only Kad
/// and suppresses the fetch (no servers to acquire for a network we skip).
#[tokio::test]
async fn per_network_overrides_are_independent() {
    // eD2k only.
    {
        let store = DurableAppConfig::new(rmule_testkit::memory_store());
        let fetcher = FakeFetcher::serving(met_one(Ipv4Addr::new(1, 2, 3, 4), 4661, "Acquired"));
        let sink = RecordingSink::default();
        // Opted into the Kad acquisition on purpose: a *disabled* Kad must
        // suppress it anyway, so the one fetch below can only be server.met.
        let outcome = run_join_sequence(
            &store,
            &fetcher,
            &opted_in(),
            &JoinConfig {
                connect_ed2k: true,
                connect_kad: false,
            },
            kad_config(),
            own_id(),
            &sink,
        )
        .await
        .unwrap();
        let commands = sink.commands();
        assert_eq!(outcome.kad_seed, KadSeedOutcome::Skipped);
        assert_eq!(fetcher.calls(), 1, "eD2k on ⇒ cold-start fetch still runs");
        assert_eq!(commands.len(), 1);
        assert_eq!(ed2k_servers(&commands).len(), 1);
    }

    // Kad only.
    {
        let store = DurableAppConfig::new(rmule_testkit::memory_store());
        let fetcher = FakeFetcher::failing(FetchError::Timeout {
            url: "http://mirror".to_owned(),
        });
        let sink = RecordingSink::default();
        let outcome = run_join_sequence(
            &store,
            &fetcher,
            &BootstrapConfig::default(),
            &JoinConfig {
                connect_ed2k: false,
                connect_kad: true,
            },
            kad_config(),
            own_id(),
            &sink,
        )
        .await
        .unwrap();
        let commands = sink.commands();
        assert_eq!(
            fetcher.calls(),
            0,
            "eD2k off ⇒ no server acquisition for a network we skip"
        );
        assert_eq!(outcome.first_run, FirstRunFetch::Skipped);
        assert_eq!(commands.len(), 1);
        assert!(matches!(commands[0], CoreCommand::EnableKad(_)));
    }
}

/// The operator opt-out: `auto_fetch_server_met = false` suppresses the
/// cold-start fetch even on an empty list, and both networks still join
/// (eD2k with no row to hand core).
#[tokio::test]
async fn auto_fetch_switch_off_suppresses_the_cold_start_fetch() {
    let store = DurableAppConfig::new(rmule_testkit::memory_store());
    let fetcher = FakeFetcher::failing(FetchError::Timeout {
        url: "http://mirror".to_owned(),
    });
    let sink = RecordingSink::default();
    let bootstrap = BootstrapConfig {
        auto_fetch_server_met: false,
        ..BootstrapConfig::default()
    };

    let outcome = run_join_sequence(
        &store,
        &fetcher,
        &bootstrap,
        &JoinConfig::default(),
        kad_config(),
        own_id(),
        &sink,
    )
    .await
    .unwrap();

    assert_eq!(outcome.first_run, FirstRunFetch::Skipped);
    assert_eq!(fetcher.calls(), 0);
    assert!(outcome.servers.is_empty());
    assert!(ed2k_servers(&sink.commands()).is_empty());
}

/// A failed cold-start fetch does not abort or retry: the joins still fire
/// (eD2k with no row to hand, Kad regardless), and the failure is reported —
/// amuled's one-shot, wait-for-the-user posture.
#[tokio::test]
async fn failed_fetch_does_not_abort_the_joins() {
    let store = DurableAppConfig::new(rmule_testkit::memory_store());
    let fetcher = FakeFetcher::failing(FetchError::Transport {
        url: "http://mirror/server.met".to_owned(),
        detail: "connection refused".to_owned(),
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

    assert!(
        matches!(outcome.first_run, FirstRunFetch::Failed(_)),
        "the fetch failure is reported, not swallowed: {:?}",
        outcome.first_run
    );
    assert_eq!(fetcher.calls(), 1, "one-shot: no retry on failure");
    assert!(outcome.servers.is_empty());
    // The eD2k join has no row to hand core; Kad joins anyway.
    let commands = sink.commands();
    assert_eq!(commands.len(), 1);
    assert!(matches!(commands[0], CoreCommand::EnableKad(_)));
}

/// Neither network: no fetch, no commands. The sequence is a no-op a
/// fully-opted-out caller can still call safely.
#[tokio::test]
async fn both_networks_disabled_is_an_inert_no_op() {
    let store = seeded_store(&[ServerEndpoint::new("9.9.9.9", 4661).unwrap()]);
    let fetcher = FakeFetcher::failing(FetchError::Timeout {
        url: "http://mirror".to_owned(),
    });
    let sink = RecordingSink::default();

    run_join_sequence(
        &store,
        &fetcher,
        &BootstrapConfig::default(),
        &JoinConfig {
            connect_ed2k: false,
            connect_kad: false,
        },
        kad_config(),
        own_id(),
        &sink,
    )
    .await
    .unwrap();

    assert_eq!(fetcher.calls(), 0);
    assert!(sink.commands().is_empty());
}

/// The auto-update walk (ADR-0065), once its switch is on: every URL walked
/// in order over the list as loaded, each URL's outcome reported, the merged
/// rows persisted before the joins, and a failing URL leaving the walk and
/// the joins going.
#[tokio::test]
async fn the_auto_update_walk_runs_at_start_behind_its_switch() {
    let persisted = ServerEndpoint::new("9.9.9.9", 4661).unwrap();
    let acquired = ServerEndpoint::new("1.2.3.4", 4661).unwrap();
    let store = seeded_store(std::slice::from_ref(&persisted));
    let fetcher = FakeFetcher::serving(met_one(Ipv4Addr::new(1, 2, 3, 4), 4661, "Walked"));
    let sink = RecordingSink::default();
    let urls = vec![
        "http://one.example/server.met".to_owned(),
        "http://two.example/server.met".to_owned(),
    ];
    let bootstrap = BootstrapConfig {
        auto_update_enabled: true,
        auto_update_urls: urls.clone(),
        ..BootstrapConfig::default()
    };

    let outcome = run_join_sequence(
        &store,
        &fetcher,
        &bootstrap,
        &JoinConfig::default(),
        kad_config(),
        own_id(),
        &sink,
    )
    .await
    .unwrap();

    assert_eq!(outcome.first_run, FirstRunFetch::Skipped);
    assert_eq!(
        outcome.auto_update,
        AutoUpdateOutcome::Walked {
            fetched: vec![
                (
                    urls[0].clone(),
                    AutoUpdateFetch::Merged {
                        added: 1,
                        updated: 0
                    }
                ),
                (
                    urls[1].clone(),
                    AutoUpdateFetch::Merged {
                        added: 0,
                        updated: 1
                    }
                ),
            ]
        }
    );
    assert_eq!(fetcher.calls(), 2, "each URL fetched once");
    assert_eq!(outcome.servers, vec![persisted.clone(), acquired.clone()]);
    assert_eq!(
        ed2k_servers(&sink.commands()),
        vec![persisted.clone(), acquired]
    );

    let failing = FakeFetcher::failing(FetchError::Timeout {
        url: urls[0].clone(),
    });
    let sink = RecordingSink::default();
    let outcome = run_join_sequence(
        &seeded_store(std::slice::from_ref(&persisted)),
        &failing,
        &bootstrap,
        &JoinConfig::default(),
        kad_config(),
        own_id(),
        &sink,
    )
    .await
    .unwrap();
    let timed_out = AutoUpdateFetch::Failed(crate::ServerListUpdateFailure::TimedOut);
    assert_eq!(
        outcome.auto_update,
        AutoUpdateOutcome::Walked {
            fetched: vec![(urls[0].clone(), timed_out), (urls[1].clone(), timed_out)]
        }
    );
    assert_eq!(
        sink.commands().len(),
        2,
        "the joins go on after a failed walk"
    );

    let off = run_join_sequence(
        &seeded_store(std::slice::from_ref(&persisted)),
        &failing,
        &BootstrapConfig {
            auto_update_enabled: false,
            ..bootstrap.clone()
        },
        &JoinConfig::default(),
        kad_config(),
        own_id(),
        &RecordingSink::default(),
    )
    .await
    .unwrap();
    assert_eq!(off.auto_update, AutoUpdateOutcome::Skipped);
}
