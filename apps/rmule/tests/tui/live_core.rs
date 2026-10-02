//! Seam proof: the REAL `Core` behind the bridge — no fakes.
//! A shared directory's add and its confirm go in through the `CoreClient`,
//! real hashing runs, the events come back over the single bus, and the pure
//! state folds them.
//! Deterministic (in-memory stores, tempfile content); the interop-bench /
//! Ghostty half is a hands-on checklist run in a real terminal.

use std::time::{Duration, Instant};

use rmule::action::Action;
use rmule::bridge::{self, BridgeConfig};
use rmule::client::CoreClient;
use rmule::state::UiState;
use rmule_core::{
    Core, CoreCommand, CoreConfig, CoreEvent, DurableAppConfig, KadIdentity, KadSeedOutcome,
    ManagedServer, ScanCommand, ScanEvent, ServeEvent, ServerListCommand, ServerListStore,
};
use rmule_primitives::ServerEndpoint;

#[tokio::test(flavor = "multi_thread")]
async fn a_real_core_share_round_trips_through_seam_bridge_and_fold() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("shared.bin"), vec![0xA5u8; 4096]).expect("write payload");

    // Production wiring on the engine's in-memory backend: `Core::builder`
    // defaults over one throwaway Durable Store.
    let core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store()).build();
    let (actions_tx, mut actions_rx) = tokio::sync::mpsc::channel(64);
    let handle = bridge::spawn(core, actions_tx, BridgeConfig::default());

    handle
        .send(CoreCommand::Scan(ScanCommand::AddSharedDirectory {
            path: dir.path().to_path_buf(),
        }))
        .await
        .expect("command lands through the seam");

    let mut state = UiState::default();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let action = actions_rx.recv().await.expect("bus open");
            // The real actor answers the bridge's own `DumpDiagnostics` poll
            // while this runs; that echo is a level the bridge lifts
            // `kad` off, never a UI event — it must not reach the bus.
            assert!(
                !matches!(&action, Action::Core(CoreEvent::DiagnosticsSnapshot { .. })),
                "the bridge's poll answer leaked onto the UI bus"
            );
            if let Action::Core(CoreEvent::Scan(ScanEvent::ConsentRequested { dir, .. })) = &action
            {
                handle
                    .send(CoreCommand::Scan(ScanCommand::Answer {
                        dir: dir.clone(),
                        share: true,
                    }))
                    .await
                    .expect("the confirm lands through the seam");
            }
            let shared = matches!(
                &action,
                Action::Core(CoreEvent::Serve(ServeEvent::FileShared { .. }))
            );
            state.apply(action, Instant::now());
            if shared {
                break;
            }
        }
    })
    .await
    .expect("FileShared must arrive within 10s");

    assert_eq!(state.shared.len(), 1, "the fold projected the share row");
    assert_eq!(state.notable.as_deref(), Some("file shared"));
    assert!(
        !state.log.is_empty(),
        "the log pane fed from the same event"
    );
}

/// The Servers tab's whole data path, end to end: the store the builder
/// is *given* is the one the table reads.
///
/// This is the wiring `rmule::attach` performs with the Durable Store —
/// the one thing that, done wrong, leaves the tab showing an empty list while
/// `rmule.redb` holds the real one. Nothing here fakes the level: the row is
/// seeded in the store before the core is built, a second arrives as an
/// operator command, and both come back on the bridge's data tick.
#[tokio::test(flavor = "multi_thread")]
async fn the_injected_server_list_store_is_what_the_servers_tab_renders() {
    let seeded = ServerEndpoint::new("10.0.0.7", 4661).expect("endpoint");
    let added = ServerEndpoint::new("10.0.0.8", 4242).expect("endpoint");

    let handle_store = rmule_testkit::memory_store();
    let store = DurableAppConfig::new(handle_store.clone());
    store
        .merge_server(ManagedServer::listed(seeded.clone()))
        .expect("seed the store before the core takes it");
    // The core's own server-list seam is the default one on this same store,
    // so the row seeded above is already there when the actor starts.
    let core = Core::builder(CoreConfig::default(), handle_store).build();

    let (actions_tx, mut actions_rx) = tokio::sync::mpsc::channel(64);
    let handle = bridge::spawn(core, actions_tx, BridgeConfig::default());
    handle
        .send(CoreCommand::ServerList(ServerListCommand::AddServer {
            server: ManagedServer::listed(added.clone()),
        }))
        .await
        .expect("command lands through the seam");

    // The level (data tick) and the edge (event stream) are two lanes with no
    // ordering between them, so wait for both rather than for whichever wins.
    let logged = format!("server added: {}:{}", added.host(), added.port());
    let mut state = UiState::default();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let action = actions_rx.recv().await.expect("bus open");
            state.apply(action, Instant::now());
            let listed = state.diagnostics.servers.len() == 2;
            let noted = state.log.iter().any(|line| *line.text == *logged);
            if listed && noted {
                break;
            }
        }
    })
    .await
    .expect("both rows on the level and the add edge in the log within 10s");

    let hosts: Vec<&str> = state
        .diagnostics
        .servers
        .iter()
        .map(|row| row.server.endpoint.host())
        .collect();
    assert_eq!(
        hosts,
        vec![seeded.host(), added.host()],
        "list order is insertion order"
    );
}

/// The Kad autoconnect wiring with its arming edge, against the
/// real core: the join `main` parks behind the run's first eD2k login starts
/// no node while it waits, and starts a real one the moment it is armed — at
/// which point the single fact the Networks panel renders (`diagnostics.kad`,
/// `None` until a node exists) goes live on the bridge's own poll.
///
/// This is the exact gap a hands-on run found: everything below this seam
/// worked, and nothing ever sent the command. The fetcher here must never be
/// called, which also pins the library's parity default (no unattended
/// nodes.dat fetch); the app opts in separately, in `main`.
#[tokio::test(flavor = "multi_thread")]
async fn the_armed_kad_join_starts_a_real_node_and_the_panel_fact_goes_live() {
    let dir = tempfile::tempdir().expect("tempdir");
    let credentials = rmule_primitives::ClientIdentity::new(
        rmule_primitives::UserHash::from_bytes([0x42; rmule_primitives::UserHash::BYTE_LEN]),
        rmule_primitives::Ed2kText::from_utf8("rmule"),
        4662,
        60,
    )
    .into();
    let kad = KadIdentity {
        id: rmule_core::KadId::from_bytes([0x11; rmule_core::KadId::BYTE_LEN]),
        udp_port: 0, // ephemeral: the app's fixed 4672 is not a test's to take
    };
    let config = rmule::kad::enable_config(dir.path(), kad, 0, &credentials);

    let core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store()).build();
    let (actions_tx, mut actions_rx) = tokio::sync::mpsc::channel(64);
    let handle = bridge::spawn(
        core,
        actions_tx,
        BridgeConfig {
            // The default 5 s Kad poll is right for a running app and far too
            // slow for a test that is waiting on exactly one of its answers.
            kad_poll_interval: Duration::from_millis(20),
            // Likewise the 1 Hz data tick: the unarmed window below is counted
            // in ticks, and each one carries several Kad poll answers.
            snapshot_interval: Duration::from_millis(50),
            ..BridgeConfig::default()
        },
    );

    // The join `main` spawns, parked on its start lane.
    let (arm, mut armed) = rmule::kad::start_lane();
    let joining = tokio::spawn({
        let client = handle.clone();
        async move {
            rmule::kad::join_on_next_start(
                &mut armed,
                &client,
                &config,
                &rmule_bootstrap::BootstrapConfig::default(),
                &NeverFetches,
            )
            .await
        }
    });

    // Unarmed, the real core stays Kad-less however long the bridge polls it:
    // the fact the panel reads is `None` because no node was ever started.
    let mut state = UiState::default();
    let mut polls = 0;
    tokio::time::timeout(Duration::from_secs(10), async {
        while polls < 3 {
            let action = actions_rx.recv().await.expect("bus open");
            polls += usize::from(matches!(action, Action::Snapshot(_)));
            state.apply(action, Instant::now());
        }
    })
    .await
    .expect("three data ticks within 10s");
    assert!(
        state.diagnostics.kad.is_none(),
        "no eD2k login yet — the join must not have fired"
    );

    let outcome = {
        arm.send(()).expect("the join task is waiting on the arm");
        joining
            .await
            .expect("the join task ran")
            .expect("armed, so the join happened")
            .expect("the join lands through the seam")
    };
    assert_eq!(
        outcome,
        KadSeedOutcome::Stranded { read_error: None },
        "no saved table and the library default acquires nothing"
    );

    // The trail `main` sends next: the app installs no tracing subscriber
    // (stdout is the alternate screen), so the seed outcome rides the same two
    // surfaces a core event's would — the log pane and the info feed.
    state.apply(
        Action::Note(rmule::words::kad::seed_outcome_words(&outcome)),
        Instant::now(),
    );
    assert_eq!(
        state.notable.as_deref(),
        Some("Kad: no saved contacts — waiting for an eD2k peer")
    );
    assert!(
        state.log.iter().any(|line| line.text.starts_with("Kad: ")),
        "the reason must survive in the log, not just flash past"
    );

    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            state.apply(actions_rx.recv().await.expect("bus open"), Instant::now());
            if let Some(kad) = state.diagnostics.kad {
                assert!(
                    !kad.contact_responded,
                    "a loopback node with no seeds has heard from nobody — 'not yet', never a lie"
                );
                break;
            }
        }
    })
    .await
    .expect("the Kad panel must go live within 10s");
}

/// The search-options row's whole path, with nothing faked between the
/// keystrokes and the wire: keys go into the real [`SearchesView`], the
/// `StartSearch` it emits goes through the real bridge into the real `Core`,
/// core's session encodes the expression tree, and the counterparty decodes it
/// back into the query it states.
///
/// The assertion is deliberately on the *server's* reading. A test that checked
/// the emitted `KeywordQuery` would prove the view built one; only a decode at
/// the far end proves the constraints survived the tree — the step where a
/// wrong tag id, a missed AND marker, or a dropped term would hide.
#[tokio::test(flavor = "multi_thread")]
async fn the_options_row_constraints_arrive_as_a_decodable_expression_tree() {
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
    use rmule::state::SessionConfig;
    use rmule::views::ViewOutcome;
    use rmule::views::searches::SearchesView;
    use rmule_core::{AppConfigStore, SearchCommand, SearchEvent};
    use rmule_primitives::Ed2kFileClass;
    use rmule_testkit::FakeEd2kServer;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    let server = FakeEd2kServer::start_scripted().await;
    let endpoint = ServerEndpoint::new(
        server.local_addr().ip().to_string(),
        server.local_addr().port(),
    )
    .expect("a loopback endpoint");

    let identity = DurableAppConfig::new(rmule_testkit::memory_store())
        .ensure_identity()
        .expect("identity");
    let mut state = UiState {
        session: Some(SessionConfig {
            server: Some(endpoint.clone()),
            credentials: rmule_core::ClientCredentials::from(identity),
            download_dir: None,
        }),
        ..UiState::default()
    };

    // The operator's gesture: `o`, pick Videos, ≥700 MB, ≤2 GB, ≥10 sources,
    // extension avi; then the phrase; then Enter.
    let mut view = SearchesView::new();
    view.handle_key(key(KeyCode::Char('o')), &state);
    view.handle_key(key(KeyCode::Right), &state); // Type: Any → Audio
    view.handle_key(key(KeyCode::Right), &state); //            → Video
    for (field_hops, text) in [(1, "700 MB"), (1, "2 GB"), (1, "10"), (1, "avi")] {
        for _ in 0..field_hops {
            view.handle_key(key(KeyCode::Tab), &state);
        }
        for c in text.chars() {
            view.handle_key(key(KeyCode::Char(c)), &state);
        }
    }
    view.handle_key(key(KeyCode::Esc), &state);
    view.handle_key(key(KeyCode::Char('/')), &state);
    for c in "bunny".chars() {
        view.handle_key(key(KeyCode::Char(c)), &state);
    }
    let ViewOutcome::Emit(Action::Command(command)) = view.handle_key(key(KeyCode::Enter), &state)
    else {
        panic!("Enter on a filtered query must emit StartSearch");
    };
    assert!(matches!(
        command,
        CoreCommand::Search(SearchCommand::StartSearch { .. })
    ));

    let core = Core::builder(
        CoreConfig {
            search_quiet_timeout: Duration::from_millis(300),
            ..CoreConfig::default()
        },
        rmule_testkit::memory_store(),
    )
    .build();
    let (actions_tx, mut actions_rx) = tokio::sync::mpsc::channel(64);
    let handle = bridge::spawn(core, actions_tx, BridgeConfig::default());
    // The operator's connect: a search dials nothing (ADR-0095).
    for connect in [
        CoreCommand::ServerList(rmule_core::ServerListCommand::AddServer {
            server: rmule_core::ManagedServer::listed(server.endpoint()),
        }),
        CoreCommand::ConnectToServer {
            server: server.endpoint(),
            credentials: rmule_testkit::test_identity(0x42, "rmule", 0).into(),
        },
    ] {
        handle.send(connect).await.expect("the connect lands");
    }
    handle
        .send(command)
        .await
        .expect("command lands through the seam");

    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let action = actions_rx.recv().await.expect("bus open");
            let settled = matches!(
                &action,
                Action::Core(CoreEvent::Search(
                    SearchEvent::SearchCompleted { .. } | SearchEvent::SearchFailed { .. }
                ))
            );
            state.apply(action, Instant::now());
            if settled {
                break;
            }
        }
    })
    .await
    .expect("the search settles within 15s");

    let queries = server.search_queries().await;
    assert_eq!(
        queries.len(),
        1,
        "exactly one OP_SEARCHREQUEST reached the server"
    );
    let query = &queries[0];
    assert_eq!(query.phrase().to_display_string(), "bunny");
    assert_eq!(query.file_type(), Some(Ed2kFileClass::Video));
    assert_eq!(query.min_size(), Some(700 * 1024 * 1024));
    assert_eq!(query.max_size(), Some(2 * 1024 * 1024 * 1024));
    assert_eq!(query.min_availability(), Some(10));
    assert_eq!(
        query
            .extension()
            .map(rmule_primitives::Ed2kText::to_display_string)
            .as_deref(),
        Some("avi"),
    );
}

/// A `Fetcher` that fails the test if the seed path ever reaches for the
/// network: with the library default switch, a cold start acquires nothing.
struct NeverFetches;

impl rmule_bootstrap::Fetcher for NeverFetches {
    fn get(
        &self,
        url: &str,
        _max_bytes: usize,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, rmule_bootstrap::FetchError>> + Send
    {
        panic!("the default-OFF nodes.dat switch must not fetch: {url}");
        #[expect(unreachable_code, reason = "the panic above is the assertion")]
        async {
            unreachable!()
        }
    }
}
