//! Unit tests for the Settings view: its fields, edits and goldens.

use super::*;
use crate::fixture::press;
use crate::golden::assert_golden;

fn state() -> UiState {
    UiState {
        preferences: Preferences {
            download_dir: Some(std::path::PathBuf::from("/home/u/Downloads")),
            temp_dir: None,
            data_dir: Some(crate::args::DataDir {
                path: std::path::PathBuf::from("/home/u/.local/share/rmule"),
                source: crate::args::DataDirSource::Home,
            }),
            nickname: "rmule".to_string(),
            tcp_port: 4662,
            udp_port: 4672,
            server_met_url: rmule_bootstrap::DEFAULT_SERVER_MET_URL.to_string(),
            auto_fetch_server_met: true,
            nodes_dat_url: rmule_bootstrap::DEFAULT_NODES_DAT_URL.to_string(),
            auto_fetch_nodes_dat: true,
            theme: ThemeChoice::Auto,
            obfuscation: ObfuscationChoice::Requested,
            port_mapping: true,
            table_sorts: crate::table_sort::TableSorts::default(),
            connect_at_start: false,
            run_log_full: false,
            last_server: None,
            player_command: None,
            dead_server_retries: 3,
            withhold_shares: false,
            remember_peers: rmule_core::RememberPeers::DEFAULT,
            user_hash: Some(rmule_primitives::UserHash::from_bytes([0x2a; 16])),
            kad_node_id: Some(rmule_core::KadId::from_bytes([0x77; 16])),
        },
        ..UiState::default()
    }
}

/// [`state`] with a download directory this platform calls absolute, for a
/// test that commits it: the goldens' `/home/u/Downloads` has no drive, so
/// Windows refuses it before any warning.
fn state_with_a_rooted_download_dir() -> UiState {
    let mut state = state();
    state.preferences.download_dir = Some(crate::fixture::rooted("home/u/Downloads"));
    state
}

fn focus_on(view: &mut SettingsView, row: Row) {
    view.form.focus = view
        .slots
        .iter()
        .position(|slot| *slot == Slot::Row(row))
        .expect("row");
}

#[test]
fn a_text_field_needs_an_edit_mode_and_a_selector_does_not() {
    let mut view = SettingsView::new();
    let state = state();

    // Browsing: a letter is a global binding, not a character.
    assert!(matches!(
        view.handle_key(press(KeyCode::Char('q')), &state),
        ViewOutcome::Ignored
    ));
    view.handle_key(press(KeyCode::Enter), &state);
    assert!(view.editing);
    view.handle_key(press(KeyCode::Char('q')), &state);
    assert!(
        view.form.text(0).ends_with('q'),
        "an open field takes every printable: {:?}",
        view.form.text(0)
    );
    view.handle_key(press(KeyCode::Esc), &state);
    assert!(!view.editing);
    assert_eq!(view.form.text(0), "/home/u/Downloads", "Esc restores");

    // A selector commits where it is stepped, with no mode at all.
    focus_on(&mut view, Row::Theme);
    match view.handle_key(press(KeyCode::Right), &state) {
        ViewOutcome::Emit(Action::Preference(PrefEdit::Theme(choice))) => {
            assert_eq!(choice, ThemeChoice::Dark);
        }
        other => panic!("expected a theme edit, got {other:?}"),
    }
    assert!(!view.editing, "a selector never opens an editor");
}

#[test]
fn a_rejected_commit_keeps_the_form_up_with_the_typing_in_it() {
    let mut view = SettingsView::new();
    let state = state();
    focus_on(&mut view, Row::TcpPort);
    view.handle_key(press(KeyCode::Enter), &state);
    for c in "abc".chars() {
        view.handle_key(press(KeyCode::Char(c)), &state);
    }
    assert!(matches!(
        view.handle_key(press(KeyCode::Enter), &state),
        ViewOutcome::Redraw
    ));
    assert!(view.editing, "the editor stays open");
    assert_eq!(
        view.form.text(view.form.focus),
        "4662abc",
        "the entry survives"
    );
    assert!(
        view.form
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("port number"),
        "{:?}",
        view.form.error
    );
}

/// A download directory is a shared directory (ADR-0101): its commit
/// has the app ask the share guards first, warns once they pass, and only
/// the `Enter` after the warning hands the app the edit.
#[test]
fn a_download_directory_commit_warns_before_it_lands() {
    let mut view = SettingsView::new();
    let state = state_with_a_rooted_download_dir();
    focus_on(&mut view, Row::DownloadDir);
    view.handle_key(press(KeyCode::Enter), &state);
    let ViewOutcome::Emit(Action::ConfirmDownloadDir(dir)) =
        view.handle_key(press(KeyCode::Enter), &state)
    else {
        panic!("the commit asks the guards first");
    };
    assert_eq!(view.form.error, None, "no warning before the guards pass");
    view.warn_share(dir);
    assert!(
        view.form
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("offered to the network"),
        "{:?}",
        view.form.error
    );
    assert!(matches!(
        view.handle_key(press(KeyCode::Enter), &state),
        ViewOutcome::Emit(Action::Preference(PrefEdit::DownloadDir(_)))
    ));
}

/// Nothing under the Temp Directory is offered, so its commit asks no guard
/// and warns of nothing: the `Enter` that ends the typing hands the app the
/// edit, and core judges where it lies at the set.
#[test]
fn a_temp_directory_commit_lands_without_a_share_warning() {
    let mut view = SettingsView::new();
    let state = state();
    let parts = crate::fixture::rooted("srv/parts");
    focus_on(&mut view, Row::TempDir);
    view.handle_key(press(KeyCode::Enter), &state);
    for c in parts.display().to_string().chars() {
        view.handle_key(press(KeyCode::Char(c)), &state);
    }
    let ViewOutcome::Emit(Action::Preference(PrefEdit::TempDir(dir))) =
        view.handle_key(press(KeyCode::Enter), &state)
    else {
        panic!("the commit is the edit");
    };
    assert_eq!(dir, Some(parts));
    assert_eq!(view.form.error, None);
}

#[test]
fn a_cancelled_download_directory_warning_asks_again() {
    let mut view = SettingsView::new();
    let state = state_with_a_rooted_download_dir();
    focus_on(&mut view, Row::DownloadDir);
    view.handle_key(press(KeyCode::Enter), &state);
    let ViewOutcome::Emit(Action::ConfirmDownloadDir(dir)) =
        view.handle_key(press(KeyCode::Enter), &state)
    else {
        panic!("the commit asks the guards first");
    };
    view.warn_share(dir);
    view.handle_key(press(KeyCode::Esc), &state);
    view.handle_key(press(KeyCode::Enter), &state);
    assert!(matches!(
        view.handle_key(press(KeyCode::Enter), &state),
        ViewOutcome::Emit(Action::ConfirmDownloadDir(_))
    ));
}

/// The two ports must not collide: aMule binds them separately and a
/// shared number silently costs the operator one of the two surfaces.
#[test]
fn the_two_listen_ports_may_not_be_set_to_each_other() {
    let mut view = SettingsView::new();
    let state = state();
    focus_on(&mut view, Row::UdpPort);
    view.handle_key(press(KeyCode::Enter), &state);
    for _ in 0..4 {
        view.handle_key(press(KeyCode::Backspace), &state);
    }
    for c in "4662".chars() {
        view.handle_key(press(KeyCode::Char(c)), &state);
    }
    view.handle_key(press(KeyCode::Enter), &state);
    assert!(
        view.form
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("must differ"),
        "{:?}",
        view.form.error
    );
}

/// The dead-server limit takes aMule's range and nothing else, and a kept
/// number is the edit core takes up.
#[test]
fn the_dead_server_limit_takes_one_to_ten_tries() {
    let mut view = SettingsView::new();
    let state = state();
    let mut typed = |text: &str| {
        focus_on(&mut view, Row::DeadServerRetries);
        view.handle_key(press(KeyCode::Enter), &state);
        for _ in 0..3 {
            view.handle_key(press(KeyCode::Backspace), &state);
        }
        for c in text.chars() {
            view.handle_key(press(KeyCode::Char(c)), &state);
        }
        let outcome = view.handle_key(press(KeyCode::Enter), &state);
        view.handle_key(press(KeyCode::Esc), &state);
        outcome
    };
    assert!(matches!(
        typed("5"),
        ViewOutcome::Emit(Action::Preference(PrefEdit::DeadServerRetries(5)))
    ));
    for refused in ["0", "11", "x"] {
        assert!(
            matches!(typed(refused), ViewOutcome::Redraw),
            "{refused} was taken"
        );
    }
}

/// `Remember peers` takes 1 to 255; a refusal says the range.
#[test]
fn remember_peers_takes_one_to_255() {
    let mut view = SettingsView::new();
    let state = state();
    let mut typed = |text: &str| {
        focus_on(&mut view, Row::RememberPeers);
        view.handle_key(press(KeyCode::Enter), &state);
        for _ in 0..3 {
            view.handle_key(press(KeyCode::Backspace), &state);
        }
        for c in text.chars() {
            view.handle_key(press(KeyCode::Char(c)), &state);
        }
        let outcome = view.handle_key(press(KeyCode::Enter), &state);
        let refusal = view.form.error.clone();
        view.handle_key(press(KeyCode::Esc), &state);
        (outcome, refusal)
    };
    let (outcome, _) = typed("255");
    assert!(matches!(
        outcome,
        ViewOutcome::Emit(Action::Preference(PrefEdit::RememberPeers(peers))) if peers.get().get() == 255
    ));
    for refused in ["0", "256", "x"] {
        let (outcome, refusal) = typed(refused);
        assert!(
            matches!(outcome, ViewOutcome::Redraw),
            "{refused} was taken"
        );
        assert_eq!(
            refusal.as_deref(),
            Some(crate::words::download::REMEMBER_PEERS_REFUSED)
        );
    }
}

/// The Player Command is split as it is typed (ADR-0114): an open quote, a
/// first word holding the file and a first word naming a folder are refused
/// under the field with nothing emitted, empty text clears it, and a command
/// that splits is kept as typed.
#[test]
fn a_player_command_is_refused_unless_its_words_split_into_a_player() {
    let dir = tempfile::tempdir().expect("temp dir");
    let folder = format!("{}/ --fs", dir.path().display());
    let mut view = SettingsView::new();
    let state = state();
    let mut typed = |text: &str| {
        focus_on(&mut view, Row::PlayerCommand);
        view.handle_key(press(KeyCode::Enter), &state);
        for c in text.chars() {
            view.handle_key(press(KeyCode::Char(c)), &state);
        }
        let outcome = view.handle_key(press(KeyCode::Enter), &state);
        let refusal = view.form.error.clone();
        view.handle_key(press(KeyCode::Esc), &state);
        (outcome, refusal)
    };
    for (refused, why) in [
        ("mpv '--title=a b", crate::player::Unsplittable::OpenQuote),
        ("%PARTFILE --fs", crate::player::Unsplittable::NoProgram),
        (&folder, crate::player::Unsplittable::Folder),
    ] {
        let (outcome, refusal) = typed(refused);
        assert!(
            matches!(outcome, ViewOutcome::Redraw),
            "{refused} was taken"
        );
        assert_eq!(
            refusal.as_deref(),
            Some(crate::words::player::field_refusal(why).as_str())
        );
    }
    let (outcome, _) = typed("  mpv --fs  ");
    assert!(matches!(
        outcome,
        ViewOutcome::Emit(Action::Preference(PrefEdit::PlayerCommand(Some(command))))
            if command == "mpv --fs"
    ));
    let (outcome, _) = typed("   ");
    assert!(matches!(
        outcome,
        ViewOutcome::Emit(Action::Preference(PrefEdit::PlayerCommand(None)))
    ));
}

#[test]
fn golden_settings_an_unset_player_says_preview_is_off() {
    let mut view = SettingsView::new();
    let state = state();
    focus_on(&mut view, Row::PlayerCommand);
    assert_golden("settings_player_unset", 78, 8, |frame| {
        view.draw(
            frame,
            frame.area(),
            &state,
            &Theme::default_dark(),
            Instant::now(),
        );
    });
}

/// The minted identity is on screen and out of reach: focus steps straight
/// past both rows, in either direction.
#[test]
fn the_full_run_log_row_is_a_selector_that_commits_its_choice() {
    let mut view = SettingsView::new();
    let state = state();
    focus_on(&mut view, Row::RunLogFull);
    view.handle_key(press(KeyCode::Char('l')), &state);
    assert!(matches!(
        view.handle_key(press(KeyCode::Enter), &state),
        ViewOutcome::Emit(Action::Preference(PrefEdit::RunLogFull(true)))
    ));
}

#[test]
fn focus_never_lands_on_a_minted_identity_row() {
    let mut view = SettingsView::new();
    let state = state();
    let display: Vec<usize> = [Row::DataDir, Row::UserHash, Row::KadNodeId]
        .iter()
        .map(|row| {
            view.slots
                .iter()
                .position(|slot| *slot == Slot::Row(*row))
                .expect("row")
        })
        .collect();
    for _ in 0..(Row::ALL.len() * 2) {
        view.handle_key(press(KeyCode::Char('j')), &state);
        assert!(
            !display.contains(&view.form.focus),
            "landed on {}",
            view.form.focus
        );
    }
    for _ in 0..(Row::ALL.len() * 2) {
        view.handle_key(press(KeyCode::Char('k')), &state);
        assert!(
            !display.contains(&view.form.focus),
            "landed on {}",
            view.form.focus
        );
    }
}

#[test]
fn golden_settings_shows_every_group_with_its_stored_values() {
    let mut view = SettingsView::new();
    let state = state();
    // The form is taller than the pane: it scrolls, and this frame shows
    // its head.
    assert_golden("settings_populated", 78, 24, |frame| {
        view.draw(
            frame,
            frame.area(),
            &state,
            &Theme::default_dark(),
            Instant::now(),
        );
    });
}

#[test]
fn golden_settings_editing_a_field_shows_the_caret_and_a_rejection() {
    let mut view = SettingsView::new();
    let state = state();
    focus_on(&mut view, Row::Nickname);
    view.handle_key(press(KeyCode::Enter), &state);
    for _ in 0..5 {
        view.handle_key(press(KeyCode::Backspace), &state);
    }
    view.handle_key(press(KeyCode::Enter), &state);
    // 30, not 22: the 21-line body (5 group
    // headers + 12 rows + 4 blanks) needs room *and* the error region's
    // own fixed 7-line box (a short message plus its reserved blank
    // padding) below it — 22 cropped both the Identity rows and most of
    // the error box unseen.
    assert_golden("settings_editing", 78, 30, |frame| {
        view.draw(
            frame,
            frame.area(),
            &state,
            &Theme::default_dark(),
            Instant::now(),
        );
    });
}

/// A UI-only run has no store, so every value is honestly absent rather
/// than a default nobody chose.
#[test]
#[cfg_attr(windows, ignore = "the golden names the Unix data-directory variables")]
fn golden_settings_without_a_config_store() {
    let mut view = SettingsView::new();
    // 23, not 22 — same room, same reason: the Kad node ID row would fall
    // off unseen here too.
    assert_golden("settings_no_store", 78, 23, |frame| {
        view.draw(
            frame,
            frame.area(),
            &UiState::default(),
            &Theme::default_dark(),
            Instant::now(),
        );
    });
}

/// The note beside the data directory names the rule that really picked it,
/// in the words `--help` uses.
#[test]
fn the_data_directory_note_names_the_rule_that_picked_it() {
    let mut state = state();
    for (source, note) in [
        (crate::args::DataDirSource::Flag, "(from --data-dir)"),
        (crate::args::DataDirSource::RmuleData, "(from RMULE_DATA)"),
        (
            crate::args::DataDirSource::XdgDataHome,
            "(from XDG_DATA_HOME)",
        ),
    ] {
        if let Some(dir) = state.preferences.data_dir.as_mut() {
            dir.source = source;
        }
        let mut view = SettingsView::new();
        let rendered = crate::golden::render_to_lines(78, 23, |frame| {
            view.draw(
                frame,
                frame.area(),
                &state,
                &Theme::default_dark(),
                Instant::now(),
            );
        });
        let row = rendered
            .lines()
            .find(|line| line.contains("Data dir"))
            .expect("the data directory row");
        assert!(row.contains(note), "{row}");
    }
}
