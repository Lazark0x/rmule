//! Unit tests for the front-end-owned configuration: the app-config seam, the preference snapshot and the edit vocabulary.

use super::*;

fn store() -> SharedConfig {
    SharedConfig::open(rmule_testkit::memory_store())
}

#[test]
fn a_loaded_snapshot_defaults_to_the_mirrors_and_the_kad_opt_in() {
    let config = store();
    let prefs = config.load(None).expect("load");
    assert_eq!(
        prefs.server_met_url,
        rmule_bootstrap::DEFAULT_SERVER_MET_URL
    );
    assert_eq!(prefs.nodes_dat_url, rmule_bootstrap::DEFAULT_NODES_DAT_URL);
    assert!(prefs.auto_fetch_nodes_dat, "the TUI's ADR-0067 opt-in");
    assert!(prefs.auto_fetch_server_met, "ADR-0065's first-run fetch");
    assert!(prefs.port_mapping, "ADR-0086's Auto");
    assert_eq!(prefs.theme, ThemeChoice::Auto);
    assert_eq!(
        prefs.obfuscation.policy(),
        rmule_core::CoreSettings::default().obfuscation,
        "unset obfuscation starts core on the library's ADR-0046 default"
    );
    assert!(!prefs.run_log_full, "the Run Log is lean until asked");
    assert_eq!(prefs.download_dir, None);
    assert_eq!(prefs.nickname, rmule_core::DEFAULT_NICKNAME);
}

/// Every edit round-trips through the store *and* folds into the snapshot,
/// so what the tab shows after a commit is what a reload would find.
#[test]
fn every_edit_persists_and_reloads_as_itself() {
    let config = store();
    let edits = [
        PrefEdit::DownloadDir(rmule_testkit::absolute_path("tmp/dl")),
        PrefEdit::Nickname("bunny".to_string()),
        PrefEdit::TcpPort(4711),
        PrefEdit::UdpPort(4722),
        PrefEdit::ServerMetUrl("https://example.invalid/server.met".to_string()),
        PrefEdit::AutoFetchServerMet(false),
        PrefEdit::NodesDatUrl("https://example.invalid/nodes.dat".to_string()),
        PrefEdit::AutoFetchNodesDat(false),
        PrefEdit::Theme(ThemeChoice::Light),
        PrefEdit::Obfuscation(ObfuscationChoice::Required),
        PrefEdit::PortMapping(false),
        PrefEdit::RunLogFull(true),
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
    assert_eq!(reloaded.nickname, "bunny");
    assert_eq!(reloaded.tcp_port, 4711);
    assert_eq!(reloaded.udp_port, 4722);
    assert!(!reloaded.auto_fetch_nodes_dat);
    assert!(!reloaded.auto_fetch_server_met);
    assert!(!reloaded.port_mapping);
    assert!(reloaded.run_log_full);
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
        receipt(PrefEdit::RunLogFull(true)).as_str(),
        "saved: full run log → on",
        "the level is read at every line written, so it needs no restart"
    );
    assert!(
        receipt(PrefEdit::Theme(ThemeChoice::Dark))
            .as_str()
            .ends_with("dark")
    );
    for waits in [
        PrefEdit::ConnectAtStart(true),
        PrefEdit::TcpPort(4662),
        PrefEdit::RememberPeers(rmule_core::RememberPeers::DEFAULT),
    ] {
        assert!(
            receipt(waits)
                .as_str()
                .ends_with("(takes effect on restart)")
        );
    }
    assert_eq!(
        receipt(PrefEdit::ServerMetUrl(
            "http://mirror.example/server.met".into()
        ))
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
        "saved: player → none"
    );
}

/// An empty Temp dir field clears the one set (ADR-0115): the commit reads
/// back unset, and the default in the data directory is in force again.
#[test]
fn an_empty_temp_dir_field_clears_the_one_set() {
    let config = store();
    let root = tempfile::tempdir().expect("temp dir");
    let parts = root.path().join("parts");
    let set = PrefEdit::TempDir(validate_temp_dir(parts.to_str().expect("utf-8")).expect("a path"));
    assert_eq!(config.commit(&set).expect("commit"), TakesEffect::NextStart);
    assert_eq!(config.load(None).expect("load").temp_dir, Some(parts));

    let cleared = PrefEdit::TempDir(validate_temp_dir("  ").expect("empty text clears"));
    assert_eq!(cleared, PrefEdit::TempDir(None));
    assert_eq!(
        config.commit(&cleared).expect("commit"),
        TakesEffect::NextStart
    );
    assert_eq!(config.load(None).expect("load").temp_dir, None);
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
    let edit = PrefEdit::Obfuscation(ObfuscationChoice::Requested);
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
