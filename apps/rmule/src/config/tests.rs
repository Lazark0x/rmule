//! Unit tests for the front-end-owned configuration: the app-config seam, the preference snapshot and the edit vocabulary.

use std::path::Path;

use super::*;
use rmule_core::Flag;
use rmule_core::port_mapping::PortMappingMode;

fn store() -> SharedConfig {
    SharedConfig::open(rmule_testkit::memory_store())
}

/// The app's own rows of an installed store, as the build before them wrote
/// them: the keys and their text are the store's format, so neither may ever
/// move. Core's rows are pinned beside its settings.
const INSTALLED_ROWS: [(&str, &str); 11] = [
    ("theme", "256"),
    ("connect_at_start", "false"),
    ("run_log_full", "true"),
    ("last_server", "198.51.100.7:4661"),
    ("player_command", "mpv --fs"),
    ("last_tab", "statistics"),
    ("terminal_title", "true"),
    ("reader_mode", "true"),
    ("completion_bell", "true"),
    ("mouse", "false"),
    ("table_sorts", "search=size:desc"),
];

/// A store written before loads as the operator left it, and saving those
/// values again writes the same rows, key for key and byte for byte.
#[test]
fn an_installed_stores_rows_load_and_save_the_same_bytes() {
    let handle = |store: &Arc<DurableStore>| CoreSettingsHandle::open(Arc::clone(store));
    let installed = rmule_testkit::memory_store();
    for (key, value) in INSTALLED_ROWS {
        handle(&installed)
            .set_front_end_value(key, value)
            .expect("row");
    }
    let loaded = SharedConfig::open(Arc::clone(&installed))
        .load(None)
        .expect("load");

    let fresh = rmule_testkit::memory_store();
    let config = SharedConfig::open(Arc::clone(&fresh));
    for edit in [
        PrefEdit::Theme(loaded.theme),
        PrefEdit::Flag(
            AppFlag::ConnectAtStart,
            loaded.flags.is_on(AppFlag::ConnectAtStart),
        ),
        PrefEdit::Flag(AppFlag::RunLogFull, loaded.flags.is_on(AppFlag::RunLogFull)),
        PrefEdit::LastServer(loaded.last_server.clone().expect("the last server")),
        PrefEdit::PlayerCommand(loaded.player_command.clone()),
        PrefEdit::LastTab(loaded.last_tab),
        PrefEdit::Flag(
            AppFlag::TerminalTitle,
            loaded.flags.is_on(AppFlag::TerminalTitle),
        ),
        PrefEdit::Flag(AppFlag::ReaderMode, loaded.flags.is_on(AppFlag::ReaderMode)),
        PrefEdit::Flag(
            AppFlag::CompletionBell,
            loaded.flags.is_on(AppFlag::CompletionBell),
        ),
        PrefEdit::Flag(AppFlag::Mouse, loaded.flags.is_on(AppFlag::Mouse)),
        PrefEdit::TableSort {
            table: "search",
            column: "size",
            direction: Direction::Descending,
        },
    ] {
        config.commit(&edit).expect("commit");
    }
    // The identity is minted per store: everything else matches.
    let saved = Preferences {
        user_hash: loaded.user_hash,
        kad_node_id: loaded.kad_node_id,
        ..config.load(None).expect("load")
    };
    assert_eq!(saved, loaded);
    for (key, value) in INSTALLED_ROWS {
        assert_eq!(
            handle(&fresh).front_end_value(key).expect("row").as_deref(),
            Some(value),
        );
    }
}

/// Text no build wrote reads as off, an on-by-default key included: the rule
/// every stored boolean has always read by.
#[test]
fn a_stored_boolean_is_on_only_as_true() {
    let store = rmule_testkit::memory_store();
    let settings = CoreSettingsHandle::open(Arc::clone(&store));
    for key in ["connect_at_start", "mouse", "reader_mode"] {
        settings.set_front_end_value(key, "yes").expect("row");
    }
    let loaded = SharedConfig::open(store).load(None).expect("load");
    assert!(!loaded.flags.is_on(AppFlag::ConnectAtStart));
    assert!(!loaded.flags.is_on(AppFlag::Mouse));
    assert!(!loaded.flags.is_on(AppFlag::ReaderMode));
}

#[test]
fn a_loaded_snapshot_defaults_to_the_mirrors_and_the_kad_opt_in() {
    let config = store();
    let prefs = config.load(None).expect("load");
    assert_eq!(
        prefs.core.server_met_url,
        rmule_bootstrap::DEFAULT_SERVER_MET_URL
    );
    assert_eq!(
        prefs.core.nodes_dat_url,
        rmule_bootstrap::DEFAULT_NODES_DAT_URL
    );
    assert!(
        prefs.core.flags.is_on(Flag::AutoFetchNodesDat),
        "the TUI's ADR-0067 opt-in"
    );
    assert!(
        prefs.core.flags.is_on(Flag::AutoFetchServerMet),
        "ADR-0065's first-run fetch"
    );
    assert_eq!(
        prefs.core.port_mapping,
        PortMappingMode::Auto,
        "ADR-0086's Auto"
    );
    assert_eq!(prefs.theme, ThemeChoice::Auto);
    assert_eq!(
        prefs.core.obfuscation,
        rmule_core::CoreSettings::default().obfuscation,
        "unset obfuscation starts core on the library's ADR-0046 default"
    );
    assert!(
        !prefs.flags.is_on(AppFlag::RunLogFull),
        "the Run Log is lean until asked"
    );
    assert_eq!(prefs.core.download_dir, None);
    assert_eq!(prefs.core.nickname, rmule_core::DEFAULT_NICKNAME);
}

/// Every edit round-trips through the store *and* folds into the snapshot,
/// so what the tab shows after a commit is what a reload would find.
#[test]
fn every_edit_persists_and_reloads_as_itself() {
    let config = store();
    let edits = [
        PrefEdit::download_dir(rmule_testkit::absolute_path("tmp/dl")),
        PrefEdit::Core(Setting::Nickname("bunny".to_string())),
        PrefEdit::Core(Setting::TcpPort(4711)),
        PrefEdit::Core(Setting::UdpPort(4722)),
        PrefEdit::Core(Setting::ServerMetUrl(
            "https://example.invalid/server.met".to_string(),
        )),
        PrefEdit::Core(Setting::Flag(Flag::AutoFetchServerMet, false)),
        PrefEdit::Core(Setting::Flag(Flag::AutoUpdateServerMet, true)),
        PrefEdit::Core(Setting::ServerMetAutoUpdateUrls(vec![
            "https://one.invalid/server.met".to_string(),
            "https://two.invalid/server.met".to_string(),
        ])),
        PrefEdit::Core(Setting::NodesDatUrl(
            "https://example.invalid/nodes.dat".to_string(),
        )),
        PrefEdit::Core(Setting::Flag(Flag::AutoFetchNodesDat, false)),
        PrefEdit::Theme(ThemeChoice::Light),
        PrefEdit::Core(Setting::Obfuscation(ObfuscationChoice::Required.policy())),
        PrefEdit::Core(Setting::PortMapping(PortMappingMode::Off)),
        PrefEdit::Flag(AppFlag::RunLogFull, true),
        PrefEdit::TableSort {
            table: "search",
            column: "size",
            direction: Direction::Descending,
        },
        PrefEdit::TableSort {
            table: "servers",
            column: "ping",
            direction: Direction::Ascending,
        },
    ];
    let mut folded = config.load(None).expect("load");
    for edit in &edits {
        config.commit(edit).expect("commit");
        folded.apply(edit);
    }

    // A reload sees every edit — including the two that live in the
    // identity rows rather than the preference table.
    let reloaded = config.load(None).expect("reload");
    assert_eq!(reloaded, folded);
    assert_eq!(reloaded.core.nickname, "bunny");
    assert_eq!(reloaded.core.tcp_port, 4711);
    assert_eq!(reloaded.core.udp_port, 4722);
    assert!(!reloaded.core.flags.is_on(Flag::AutoFetchNodesDat));
    assert!(!reloaded.core.flags.is_on(Flag::AutoFetchServerMet));
    assert_eq!(reloaded.core.port_mapping, PortMappingMode::Off);
    assert!(reloaded.flags.is_on(AppFlag::RunLogFull));
    // Two tables' sorts share one stored value without clobbering.
    assert_eq!(
        reloaded.table_sorts.get("search"),
        Some(("size", Direction::Descending))
    );
    assert_eq!(
        reloaded.table_sorts.get("servers"),
        Some(("ping", Direction::Ascending))
    );
}

/// The receipt reads when the commit says the edit takes effect: the app's
/// own keys apply at once, connect at start waits for a start, and with no
/// core running every core key waits for the next one.
#[test]
fn a_receipt_names_the_restart_exactly_when_the_edit_waits_for_one() {
    let config = store();
    let receipt = |edit: PrefEdit| {
        let effect = config.commit(&edit).expect("commit");
        crate::words::app::receipt(&edit, effect)
    };
    assert_eq!(
        receipt(PrefEdit::Flag(AppFlag::RunLogFull, true)).as_str(),
        "saved: full run log → on",
        "the level is read at every line written, so it needs no restart"
    );
    assert!(
        receipt(PrefEdit::Theme(ThemeChoice::Dark))
            .as_str()
            .ends_with("dark")
    );
    for waits in [
        PrefEdit::Flag(AppFlag::ConnectAtStart, true),
        PrefEdit::Core(Setting::TcpPort(4662)),
        PrefEdit::Core(Setting::RememberPeers(rmule_core::RememberPeers::DEFAULT)),
    ] {
        assert!(
            receipt(waits)
                .as_str()
                .ends_with("(takes effect on restart)")
        );
    }
    assert_eq!(
        receipt(PrefEdit::Core(Setting::ServerMetUrl(
            "http://mirror.example/server.met".into()
        )))
        .as_str(),
        "saved: server.met URL → http://mirror.example/server.met \
         (the next server list update uses it)",
        "the update form opens on the stored URL, so no restart stands between"
    );
}

/// The Player Command is the app's own key (ADR-0114): a commit takes effect
/// at once with no core running, reads back from the store, and empty text
/// reads back as unset.
#[test]
fn a_player_command_commits_at_once_and_an_empty_one_reads_back_unset() {
    let config = store();
    let set = PrefEdit::PlayerCommand(Some("mpv --fs %PARTFILE".to_string()));
    assert_eq!(config.commit(&set).expect("commit"), TakesEffect::Now);
    assert_eq!(
        config.load(None).expect("load").player_command.as_deref(),
        Some("mpv --fs %PARTFILE")
    );
    assert_eq!(
        crate::words::app::receipt(&set, TakesEffect::Now).as_str(),
        "saved: player → mpv --fs %PARTFILE"
    );

    let cleared = PrefEdit::PlayerCommand(None);
    assert_eq!(config.commit(&cleared).expect("commit"), TakesEffect::Now);
    assert_eq!(config.load(None).expect("load").player_command, None);
    assert_eq!(
        crate::words::app::receipt(&cleared, TakesEffect::Now).as_str(),
        "saved: player → the default app"
    );
}

/// An empty Temp dir field clears the one set (ADR-0115): the commit reads
/// back unset, and the default in the data directory is in force again.
#[test]
fn an_empty_temp_dir_field_clears_the_one_set() {
    let config = store();
    let root = tempfile::tempdir().expect("temp dir");
    let parts = root.path().join("parts");
    let set = PrefEdit::Core(Setting::TempDir(
        validate_temp_dir(parts.to_str().expect("utf-8")).expect("a path"),
    ));
    assert_eq!(config.commit(&set).expect("commit"), TakesEffect::NextStart);
    assert_eq!(config.load(None).expect("load").core.temp_dir, Some(parts));

    let cleared = PrefEdit::Core(Setting::TempDir(
        validate_temp_dir("  ").expect("empty text clears"),
    ));
    assert_eq!(cleared, PrefEdit::Core(Setting::TempDir(None)));
    assert_eq!(
        config.commit(&cleared).expect("commit"),
        TakesEffect::NextStart
    );
    assert_eq!(config.load(None).expect("load").core.temp_dir, None);
    assert_eq!(
        crate::words::app::receipt(&cleared, TakesEffect::NextStart).as_str(),
        "saved: Temp Directory → the default (takes effect on restart)"
    );
}

/// On a running core the obfuscation policy is live (ADR-0046): the commit
/// answers that it took effect at once, and the receipt names no restart.
#[tokio::test]
async fn an_obfuscation_edit_on_a_running_core_takes_effect_at_once() {
    let store = rmule_testkit::memory_store();
    let core = rmule_core::Core::builder(rmule_core::CoreConfig::default(), store.clone())
        .settings(rmule_core::CoreSettings::default())
        .build();
    let config = SharedConfig::new(core.settings(), DurableAppConfig::new(store));
    let edit = PrefEdit::Core(Setting::Obfuscation(ObfuscationChoice::Requested.policy()));
    let effect = config.commit(&edit).expect("commit");
    assert_eq!(effect, TakesEffect::Now);
    assert_eq!(
        crate::words::app::receipt(&edit, effect).as_str(),
        "saved: obfuscation → requested"
    );
    core.shutdown().await;
}

#[test]
fn a_download_directory_must_be_absolute_and_not_an_existing_file() {
    assert!(validate_download_dir("  ").is_err());
    assert!(validate_download_dir("downloads").is_err(), "relative");
    let absolute = crate::fixture::rooted("tmp/rmule-dl");
    assert_eq!(
        validate_download_dir(&format!(" {} ", absolute.display())),
        Ok(absolute)
    );
    let file = tempfile::NamedTempFile::new().expect("temp file");
    assert!(
        validate_download_dir(file.path().to_str().expect("utf-8")).is_err(),
        "an existing file is a typo, not a directory"
    );
}

#[test]
fn a_nickname_must_be_something_a_hello_can_carry() {
    assert!(validate_nickname("   ").is_err());
    assert!(validate_nickname("bad\u{7}name").is_err());
    assert_eq!(validate_nickname("  rmule  "), Ok("rmule".to_string()));
}

#[test]
fn a_leading_tilde_is_the_operators_home_and_nothing_else_is() {
    let home = || Some(PathBuf::from("/home/op"));
    assert_eq!(under_home("~", home()), PathBuf::from("/home/op"));
    assert_eq!(under_home("~/dl", home()), Path::new("/home/op").join("dl"));
    assert_eq!(under_home("~op/dl", home()), PathBuf::from("~op/dl"));
    assert_eq!(under_home("/srv/~/dl", home()), PathBuf::from("/srv/~/dl"));
    assert_eq!(under_home("~/dl", None), PathBuf::from("~/dl"));
}

/// Connect at start reads on from a store that never heard of it, and an off
/// the store holds is the operator's and stays: the default is the value,
/// not a rung that would turn their choice over.
#[test]
fn connect_at_start_is_on_unless_the_operator_stored_off() {
    let config = SharedConfig::open(rmule_testkit::memory_store());
    let connect_at_start = |config: &SharedConfig| {
        let flags = config.load(None).expect("load").flags;
        flags.is_on(AppFlag::ConnectAtStart)
    };
    assert!(connect_at_start(&config));

    config
        .commit(&PrefEdit::Flag(AppFlag::ConnectAtStart, false))
        .expect("commit");
    assert!(!connect_at_start(&config));

    config
        .commit(&PrefEdit::Flag(AppFlag::ConnectAtStart, true))
        .expect("commit");
    assert!(connect_at_start(&config));
}

/// The two opt-ins start off, and the tab comes back as it was left.
#[test]
fn the_last_tab_and_the_opt_ins_read_back() {
    let config = SharedConfig::open(rmule_testkit::memory_store());
    let fresh = config.load(None).expect("load");
    assert_eq!(fresh.last_tab, crate::view::ViewId::Networks);
    assert!(!fresh.flags.is_on(AppFlag::TerminalTitle));
    assert!(!fresh.flags.is_on(AppFlag::CompletionBell));
    assert!(
        fresh.flags.is_on(AppFlag::Mouse),
        "an unset key takes the mouse"
    );

    for edit in [
        PrefEdit::Flag(AppFlag::Mouse, false),
        PrefEdit::LastTab(crate::view::ViewId::Transfers),
        PrefEdit::Flag(AppFlag::TerminalTitle, true),
        PrefEdit::Flag(AppFlag::ReaderMode, true),
        PrefEdit::Flag(AppFlag::CompletionBell, true),
    ] {
        config.commit(&edit).expect("commit");
    }
    let stored = config.load(None).expect("load");
    assert_eq!(stored.last_tab, crate::view::ViewId::Transfers);
    assert!(stored.flags.is_on(AppFlag::TerminalTitle));
    assert!(stored.flags.is_on(AppFlag::CompletionBell));
    assert!(stored.flags.is_on(AppFlag::ReaderMode));
    assert!(!stored.flags.is_on(AppFlag::Mouse));
}
