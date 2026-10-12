//! The managed server list as a core surface (ADR-0080): the CRUD commands,
//! their edge events, the on-demand server.met update, and the level every
//! consumer reads the list off.
//!
//! Everything here drives a real `Core` actor — commands in, events out, level
//! read back through the sync `diagnostics_snapshot` accessor — because the
//! contract under test is the actor's, not the store's (the store's own fold
//! is pinned in `server_list.rs` and `app_config.rs`).

use rmule_testkit::HANG_GUARD;
use std::net::Ipv4Addr;
use std::sync::Arc;

use rmule_bootstrap::{FetchError, Fetcher};
use rmule_core::{
    Core, CoreCommand, CoreCommandRejectReason, CoreConfig, CoreEvent, DurableAppConfig,
    ManagedServer, ServerListCommand, ServerListEvent, ServerListStore, ServerPriority,
};
use rmule_primitives::{Ed2kText, Ipv4Endpoint, ServerEndpoint, Tag, TagName, TagValue};

use crate::fixture::open_store;
use tokio::sync::Notify;
use tokio::time::{Duration, timeout};

// --- fixtures ---------------------------------------------------------------

const TAG_SERVERNAME: u8 = 0x01;
const TAG_DESCRIPTION: u8 = 0x0B;

fn endpoint(host: &str, port: u16) -> ServerEndpoint {
    ServerEndpoint::new(host, port).expect("valid endpoint")
}

/// Deterministic server.met bytes (crate-built, not an aMule capture).
fn met_bytes(rows: &[(Ipv4Addr, u16, &str, &str)]) -> Vec<u8> {
    let mut bytes = vec![0xE0u8];
    bytes.extend_from_slice(&u32::try_from(rows.len()).unwrap().to_le_bytes());
    for (ip, port, name, description) in rows {
        let mut tags = vec![Tag::new(
            TagName::compact_id(TAG_SERVERNAME),
            TagValue::String(Ed2kText::from_utf8(*name)),
        )];
        if !description.is_empty() {
            tags.push(Tag::new(
                TagName::compact_id(TAG_DESCRIPTION),
                TagValue::String(Ed2kText::from_utf8(*description)),
            ));
        }
        bytes.extend_from_slice(&Ipv4Endpoint::new(*ip, *port).encode());
        bytes.extend_from_slice(&u32::try_from(tags.len()).unwrap().to_le_bytes());
        for tag in &tags {
            bytes.extend(tag.encode());
        }
    }
    bytes
}

/// A canned-bytes fetcher: no socket opens anywhere in this file.
struct FakeFetcher {
    result: Result<Vec<u8>, FetchError>,
    /// When set, the fetch parks on it — a deterministic "still in flight".
    park: Option<Arc<Notify>>,
}

impl FakeFetcher {
    fn serving(bytes: Vec<u8>) -> Self {
        Self {
            result: Ok(bytes),
            park: None,
        }
    }

    fn failing() -> Self {
        Self {
            result: Err(FetchError::Timeout {
                url: "http://mirror/server.met".to_owned(),
            }),
            park: None,
        }
    }

    fn parked(park: Arc<Notify>) -> Self {
        Self {
            result: Ok(met_bytes(&[])),
            park: Some(park),
        }
    }
}

impl Fetcher for FakeFetcher {
    fn get(
        &self,
        _url: &str,
        _max_bytes: usize,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, FetchError>> + Send {
        let result = self.result.clone();
        let park = self.park.clone();
        async move {
            if let Some(park) = park {
                park.notified().await;
            }
            result
        }
    }
}

/// A config whose status-ping sweep is parked. These tests are about the list
/// model — the fold, the commands, the level — and the sweep is a second,
/// legitimate writer of the very failure tally they assert (ADR-0080 amendment:
/// a probe counts a failure at send). Parking it keeps each assertion about the
/// one writer under test.
fn list_only() -> CoreConfig {
    CoreConfig {
        status_ping_tick: Duration::from_secs(3600),
        ..CoreConfig::default()
    }
}

async fn send(core: &Core, command: ServerListCommand) {
    core.send(CoreCommand::ServerList(command))
        .await
        .expect("core accepts the command");
}

/// The next server-list edge or rejection, whichever comes first. Any other
/// cross-activity chatter is walked past.
async fn next_answer(core: &mut Core) -> CoreEvent {
    timeout(HANG_GUARD, async {
        loop {
            match core.next_event().await.expect("core is alive") {
                event @ (CoreEvent::ServerList(_) | CoreEvent::CommandRejected { .. }) => {
                    return event;
                }
                _ => continue,
            }
        }
    })
    .await
    .expect("an answer within the deadline")
}

async fn next_edge(core: &mut Core) -> ServerListEvent {
    match next_answer(core).await {
        CoreEvent::ServerList(event) => event,
        other => panic!("expected a server-list edge, got {other:?}"),
    }
}

async fn next_rejection(core: &mut Core) -> CoreCommandRejectReason {
    match next_answer(core).await {
        CoreEvent::CommandRejected { reason } => reason,
        other => panic!("expected a rejection, got {other:?}"),
    }
}

fn listed(core: &Core) -> Vec<ManagedServer> {
    core.diagnostics_snapshot()
        .servers
        .into_iter()
        .map(|row| row.server)
        .collect()
}

// --- the CRUD arc -----------------------------------------------------------

/// The whole operator arc over one row: add it, re-add it (a fold, not a
/// duplicate), re-prioritise it, pin it, drop it — each answered with its own
/// edge, and each visible on the level immediately after.
#[tokio::test]
async fn the_crud_arc_reports_edges_and_moves_the_level() {
    let mut core = Core::builder(list_only(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();
    let server = endpoint("1.2.3.4", 4661);

    send(
        &core,
        ServerListCommand::AddServer {
            server: ManagedServer {
                endpoint: server.clone(),
                name: Ed2kText::from_utf8("First Name"),
                description: Ed2kText::from_utf8("A blurb"),
                priority: ServerPriority::High,
                is_static: false,
                fail_count: 0,
                figures: None,
                grants: None,
                udp_crypt: None,
                aux_ports: None,
                listed_udp_flags: None,
            },
        },
    )
    .await;
    assert_eq!(
        next_edge(&mut core).await,
        ServerListEvent::ServerAdded {
            server: server.clone()
        }
    );
    let rows = listed(&core);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].name.to_display_string(), "First Name");
    assert_eq!(rows[0].priority, ServerPriority::High);

    // A re-add of a known endpoint folds: the name takes, the priority does
    // not — that is what SetServerPriority is for.
    send(
        &core,
        ServerListCommand::AddServer {
            server: ManagedServer {
                endpoint: server.clone(),
                name: Ed2kText::from_utf8("Second Name"),
                description: Ed2kText::from_bytes(Vec::new()),
                priority: ServerPriority::Low,
                is_static: false,
                fail_count: 0,
                figures: None,
                grants: None,
                udp_crypt: None,
                aux_ports: None,
                listed_udp_flags: None,
            },
        },
    )
    .await;
    assert_eq!(
        next_edge(&mut core).await,
        ServerListEvent::ServerUpdated {
            server: server.clone()
        }
    );
    let rows = listed(&core);
    assert_eq!(rows.len(), 1, "a fold is not a second row");
    assert_eq!(rows[0].name.to_display_string(), "Second Name");
    assert_eq!(rows[0].description.to_display_string(), "A blurb");
    assert_eq!(rows[0].priority, ServerPriority::High);

    send(
        &core,
        ServerListCommand::SetServerPriority {
            server: server.clone(),
            priority: ServerPriority::Low,
        },
    )
    .await;
    assert_eq!(
        next_edge(&mut core).await,
        ServerListEvent::ServerPriorityChanged {
            server: server.clone(),
            priority: ServerPriority::Low,
        }
    );
    assert_eq!(listed(&core)[0].priority, ServerPriority::Low);

    send(
        &core,
        ServerListCommand::SetServerStatic {
            server: server.clone(),
            is_static: true,
        },
    )
    .await;
    assert_eq!(
        next_edge(&mut core).await,
        ServerListEvent::ServerStaticChanged {
            server: server.clone(),
            is_static: true,
        }
    );
    assert!(listed(&core)[0].is_static);

    send(
        &core,
        ServerListCommand::RemoveServer {
            server: server.clone(),
        },
    )
    .await;
    assert_eq!(
        next_edge(&mut core).await,
        ServerListEvent::ServerRemoved { server }
    );
    assert!(listed(&core).is_empty());
}

/// A row that is not there cannot be removed, re-prioritised or pinned — each
/// is refused by name rather than silently doing nothing.
#[tokio::test]
async fn commands_naming_an_unlisted_server_are_refused() {
    let mut core = Core::builder(list_only(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();
    let absent = endpoint("9.9.9.9", 4661);

    for command in [
        ServerListCommand::RemoveServer {
            server: absent.clone(),
        },
        ServerListCommand::SetServerPriority {
            server: absent.clone(),
            priority: ServerPriority::High,
        },
        ServerListCommand::SetServerStatic {
            server: absent.clone(),
            is_static: true,
        },
    ] {
        send(&core, command).await;
        assert_eq!(
            next_rejection(&mut core).await,
            CoreCommandRejectReason::UnknownServer
        );
    }
}

// --- the swept list follows the list ---------------------------------------

/// A server-UDP socket standing in for a listed server, and the TCP endpoint
/// the list holds for it (the sweep sends to its TCP port + 4).
async fn udp_server() -> (tokio::net::UdpSocket, ServerEndpoint) {
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let tcp_port = udp.local_addr().unwrap().port() - 4;
    (udp, endpoint("127.0.0.1", tcp_port))
}

/// Search once and wait for the search to complete: its sweep has sent its
/// last datagram by then.
async fn search_to_completion(core: &mut Core, phrase: &str) {
    let search_id = crate::fixture::start_search(core, crate::fixture::search_query(phrase)).await;
    crate::fixture::next_expected(core, "the search to complete", |event| {
        matches!(
            event,
            CoreEvent::Search(rmule_core::SearchEvent::SearchCompleted { search_id: id, .. })
                if *id == search_id
        )
    })
    .await;
}

/// The Global Search Sweep walks the Managed Server List as it stands when
/// a search starts (aMule `SearchList.cpp:903-913`, kno's fork): a server the
/// operator adds mid-run is asked, one a server.met import brings is asked,
/// and one the operator removes is asked no more.
#[tokio::test]
async fn the_search_sweep_follows_the_list_through_add_import_and_remove() {
    use crate::fixture::sweep_datagram;

    let (added_udp, added) = udp_server().await;
    let (imported_udp, imported) = udp_server().await;
    let connected = rmule_testkit::FakeEd2kServer::start_scripted().await;
    let mut core = Core::builder(
        CoreConfig {
            global_search_tick: Duration::from_millis(5),
            ..crate::fixture::search_config()
        },
        rmule_testkit::memory_store(),
    )
    .settings(rmule_core::CoreSettings::default())
    .server_list_fetcher(FakeFetcher::serving(met_bytes(&[(
        Ipv4Addr::LOCALHOST,
        imported.port(),
        "Imported",
        "",
    )])))
    .build();
    crate::fixture::connect_and_settle(&mut core, &connected.endpoint()).await;
    let quiet = Duration::from_millis(200);

    crate::fixture::list_server(&core, &added).await;
    search_to_completion(&mut core, "first").await;
    assert!(
        sweep_datagram(&added_udp, quiet).await.is_some(),
        "a server added mid-run is swept"
    );

    send(
        &core,
        ServerListCommand::UpdateServerList {
            url: "http://mirror/server.met".to_owned(),
        },
    )
    .await;
    crate::fixture::next_expected(&mut core, "the import to land", |event| {
        matches!(
            event,
            CoreEvent::ServerList(ServerListEvent::ServerListUpdated { added: 1, .. })
        )
    })
    .await;
    search_to_completion(&mut core, "second").await;
    assert!(
        sweep_datagram(&imported_udp, quiet).await.is_some(),
        "a server a server.met import brings mid-run is swept"
    );
    assert!(sweep_datagram(&added_udp, quiet).await.is_some());

    send(&core, ServerListCommand::RemoveServer { server: added }).await;
    search_to_completion(&mut core, "third").await;
    assert!(sweep_datagram(&imported_udp, quiet).await.is_some());
    assert_eq!(
        sweep_datagram(&added_udp, quiet).await,
        None,
        "a removed server is swept no more"
    );
}

// --- the on-demand update ---------------------------------------------------

/// aMule's "update server.met from URL", on the actor: the download appends
/// what is new, folds what is known — keeping the operator's priority, pin and
/// failure tally — and the level carries the result.
#[tokio::test]
async fn an_update_merges_the_mirror_into_the_list() {
    let mut core = Core::builder(list_only(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .server_list_fetcher(FakeFetcher::serving(met_bytes(&[
            (Ipv4Addr::new(1, 2, 3, 4), 4661, "Renamed", "Fresh blurb"),
            (Ipv4Addr::new(5, 6, 7, 8), 4662, "Brand New", ""),
        ])))
        .build();
    let known = endpoint("1.2.3.4", 4661);

    send(
        &core,
        ServerListCommand::AddServer {
            server: ManagedServer {
                endpoint: known.clone(),
                name: Ed2kText::from_utf8("Known"),
                description: Ed2kText::from_bytes(Vec::new()),
                priority: ServerPriority::High,
                is_static: true,
                fail_count: 4,
                figures: None,
                grants: None,
                udp_crypt: None,
                aux_ports: None,
                listed_udp_flags: None,
            },
        },
    )
    .await;
    assert!(matches!(
        next_edge(&mut core).await,
        ServerListEvent::ServerAdded { .. }
    ));

    send(
        &core,
        ServerListCommand::UpdateServerList {
            url: "http://mirror/server.met".to_owned(),
        },
    )
    .await;
    assert_eq!(
        next_edge(&mut core).await,
        ServerListEvent::ServerListUpdateStarted {
            url: "http://mirror/server.met".to_owned()
        },
        "an accepted update is observable before its outcome"
    );
    assert_eq!(
        next_edge(&mut core).await,
        ServerListEvent::ServerListUpdated {
            added: 1,
            updated: 1,
            total: 2,
        }
    );

    let rows = listed(&core);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].name.to_display_string(), "Renamed");
    assert_eq!(rows[0].description.to_display_string(), "Fresh blurb");
    assert_eq!(rows[0].priority, ServerPriority::High, "priority is ours");
    assert!(rows[0].is_static, "the pin is ours");
    assert_eq!(rows[0].fail_count, 4, "the failure tally is ours");
    assert_eq!(rows[1].endpoint, endpoint("5.6.7.8", 4662));
    assert_eq!(rows[1].name.to_display_string(), "Brand New");
}

/// A failed fetch is reported and changes nothing — ADR-0065's
/// parse-before-install seen from the command surface.
#[tokio::test]
async fn a_failed_update_leaves_the_list_untouched() {
    let mut core = Core::builder(list_only(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .server_list_fetcher(FakeFetcher::failing())
        .build();
    let known = endpoint("1.2.3.4", 4661);
    send(
        &core,
        ServerListCommand::AddServer {
            server: ManagedServer::listed(known.clone()),
        },
    )
    .await;
    assert!(matches!(
        next_edge(&mut core).await,
        ServerListEvent::ServerAdded { .. }
    ));

    send(
        &core,
        ServerListCommand::UpdateServerList {
            url: "http://mirror/server.met".to_owned(),
        },
    )
    .await;
    assert!(matches!(
        next_edge(&mut core).await,
        ServerListEvent::ServerListUpdateStarted { .. }
    ));
    assert_eq!(
        next_edge(&mut core).await,
        ServerListEvent::ServerListUpdateFailed {
            reason: rmule_core::ServerListUpdateFailure::TimedOut
        },
        "the failure is reported as a code, not swallowed"
    );

    let rows = listed(&core);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].endpoint, known);
}

/// Honest Capability Advertisement: core links no HTTP client, so a core built
/// without a fetcher refuses the update instead of quietly ignoring it.
#[tokio::test]
async fn an_update_without_a_fetch_capability_is_refused() {
    let mut core = Core::builder(list_only(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .build();

    send(
        &core,
        ServerListCommand::UpdateServerList {
            url: "http://mirror/server.met".to_owned(),
        },
    )
    .await;

    assert_eq!(
        next_rejection(&mut core).await,
        CoreCommandRejectReason::ServerListFetchUnavailable
    );
}

/// One update at a time, and the actor is not the thing waiting: while a fetch
/// is parked, a second update is refused *and* an unrelated CRUD command is
/// still answered.
#[tokio::test]
async fn a_second_update_is_refused_while_the_first_is_still_fetching() {
    let park = Arc::new(Notify::new());
    let mut core = Core::builder(list_only(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .server_list_fetcher(FakeFetcher::parked(Arc::clone(&park)))
        .build();

    send(
        &core,
        ServerListCommand::UpdateServerList {
            url: "http://mirror/server.met".to_owned(),
        },
    )
    .await;
    assert!(matches!(
        next_edge(&mut core).await,
        ServerListEvent::ServerListUpdateStarted { .. }
    ));

    send(
        &core,
        ServerListCommand::UpdateServerList {
            url: "http://mirror/server.met".to_owned(),
        },
    )
    .await;
    assert_eq!(
        next_rejection(&mut core).await,
        CoreCommandRejectReason::ServerListUpdateInFlight
    );

    // The actor is free while the fetch is parked.
    let server = endpoint("1.2.3.4", 4661);
    send(
        &core,
        ServerListCommand::AddServer {
            server: ManagedServer::listed(server.clone()),
        },
    )
    .await;
    assert_eq!(
        next_edge(&mut core).await,
        ServerListEvent::ServerAdded { server }
    );

    // Releasing the fetch lands the update, and the guard is released with it.
    park.notify_one();
    assert!(matches!(
        next_edge(&mut core).await,
        ServerListEvent::ServerListUpdated { .. }
    ));
    send(
        &core,
        ServerListCommand::UpdateServerList {
            url: "http://mirror/server.met".to_owned(),
        },
    )
    .await;
    assert!(matches!(
        next_edge(&mut core).await,
        ServerListEvent::ServerListUpdateStarted { .. }
    ));
}

// --- the level --------------------------------------------------------------

/// The list is a level from the actor's first instant: a consumer that snapshots
/// before sending anything already sees what the store held, with the dynamic
/// facts honestly unknown.
#[tokio::test]
async fn a_handed_over_list_is_on_the_level_before_any_command() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(dir.path());
    DurableAppConfig::new(Arc::clone(&store))
        .merge_server(ManagedServer {
            endpoint: endpoint("1.2.3.4", 4661),
            name: Ed2kText::from_utf8("Persisted"),
            description: Ed2kText::from_bytes(Vec::new()),
            priority: ServerPriority::Low,
            is_static: true,
            fail_count: 9,
            figures: None,
            grants: None,
            udp_crypt: None,
            aux_ports: None,
            listed_udp_flags: None,
        })
        .unwrap();

    let core = Core::builder(list_only(), store)
        .settings(rmule_core::CoreSettings::default())
        .build();
    // The actor publishes before it takes its first command, so the very next
    // snapshot carries the list.
    let snapshot = timeout(HANG_GUARD, async {
        loop {
            let snapshot = core.diagnostics_snapshot();
            if !snapshot.servers.is_empty() {
                return snapshot;
            }
            // A polled level: the snapshot has no watch to
            // await, so this sleep-polls rather than spinning a core.
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the handed-over list reaches the level");

    assert_eq!(snapshot.servers.len(), 1);
    let row = &snapshot.servers[0];
    assert_eq!(row.server.name.to_display_string(), "Persisted");
    assert_eq!(row.server.priority, ServerPriority::Low);
    assert!(row.server.is_static);
    assert_eq!(row.server.fail_count, 9);
    assert_eq!(row.ping, None, "never measured is unknown, not zero");
    assert_eq!(row.users, None);
    assert_eq!(row.files, None);
}

/// A command's effect is durable, not just published: what the actor wrote is
/// what a second reader of the same file sees once the actor is gone.
///
/// The reader is a second seam handle on the same open store rather than a
/// reopened one, because one process holds one engine per file (ADR-0083) and
/// the actor's own handle outlives `shutdown` by however long its task takes
/// to unwind. What a genuine restart reads back is pinned field by field in
/// `store_app_config.rs`.
#[tokio::test]
async fn crud_lands_in_the_durable_store() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(dir.path());
    let server = endpoint("1.2.3.4", 4661);

    {
        let mut core = Core::builder(list_only(), Arc::clone(&store))
            .settings(rmule_core::CoreSettings::default())
            .build();
        send(
            &core,
            ServerListCommand::AddServer {
                server: ManagedServer {
                    endpoint: server.clone(),
                    name: Ed2kText::from_utf8("Durable"),
                    description: Ed2kText::from_bytes(Vec::new()),
                    priority: ServerPriority::Normal,
                    is_static: false,
                    fail_count: 0,
                    figures: None,
                    grants: None,
                    udp_crypt: None,
                    aux_ports: None,
                    listed_udp_flags: None,
                },
            },
        )
        .await;
        assert!(matches!(
            next_edge(&mut core).await,
            ServerListEvent::ServerAdded { .. }
        ));
        send(
            &core,
            ServerListCommand::SetServerStatic {
                server: server.clone(),
                is_static: true,
            },
        )
        .await;
        assert!(matches!(
            next_edge(&mut core).await,
            ServerListEvent::ServerStaticChanged { .. }
        ));
        core.shutdown().await;
    }

    let rows = DurableAppConfig::new(store).servers().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].endpoint, server);
    assert_eq!(rows[0].name.to_display_string(), "Durable");
    assert!(rows[0].is_static);
}
