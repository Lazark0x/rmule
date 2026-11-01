//! Unit tests for the action reducer: how a bus action becomes a state change, a command or a flash.

use super::*;
use crate::config::AppFlag;
use crate::fixture::key_action;
use crate::theme::Theme;
use crate::view::ViewId;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use rmule_core::Setting;

fn release(code: KeyCode) -> Action {
    Action::Input(Event::Key(KeyEvent::new_with_kind(
        code,
        KeyModifiers::NONE,
        KeyEventKind::Release,
    )))
}

fn chord(code: KeyCode, modifiers: KeyModifiers) -> Action {
    Action::Input(Event::Key(KeyEvent::new(code, modifiers)))
}

/// Windows reports a release for every key: one press types one letter, on
/// the tabs that read their keys raw too.
#[test]
fn a_release_never_acts_on_any_surface() {
    let now = Instant::now();
    let mut app = App::new(Theme::default_dark());
    app.reduce(key_action(KeyCode::Char('2')), now);
    app.reduce(key_action(KeyCode::Char('b')), now);
    app.reduce(release(KeyCode::Char('b')), now);
    assert_eq!(app.views.searches.query_text(), "b");
    app.reduce(key_action(KeyCode::Esc), now);
    for view in ViewId::ALL {
        app.chrome.active = view;
        assert!(matches!(
            app.reduce(release(KeyCode::Char('q')), now),
            Flow::Continue
        ));
    }
}

/// The reflex every terminal user has: Ctrl-C leaves, from every tab and over
/// any modal, and is never the tab's own `c`.
#[test]
fn ctrl_c_quits_from_every_surface_and_never_toggles_the_server() {
    let now = Instant::now();
    let ctrl_c = || chord(KeyCode::Char('c'), KeyModifiers::CONTROL);
    let mut app = App::new(Theme::default_dark());
    for view in ViewId::ALL {
        app.chrome.active = view;
        assert!(matches!(app.reduce(ctrl_c(), now), Flow::Quit), "{view:?}");
    }
    app.chrome.help_open = true;
    assert!(matches!(app.reduce(ctrl_c(), now), Flow::Quit));
    assert!(app.pending_commands.is_empty());
}

#[test]
fn a_chord_reaches_no_view_and_altgr_is_text() {
    let now = Instant::now();
    let mut app = App::new(Theme::default_dark());
    app.reduce(key_action(KeyCode::Char('2')), now);
    app.reduce(chord(KeyCode::Char('w'), KeyModifiers::CONTROL), now);
    app.reduce(chord(KeyCode::Char('b'), KeyModifiers::ALT), now);
    assert_eq!(app.views.searches.query_text(), "");
    let alt_gr = KeyModifiers::CONTROL | KeyModifiers::ALT;
    app.reduce(chord(KeyCode::Char('@'), alt_gr), now);
    assert_eq!(app.views.searches.query_text(), "@");
}

/// `q` is one letter on the wrong tab away: over a running download it asks,
/// `y` leaves, anything that declines stays, and a second Ctrl-C is the answer.
/// A chord the line editor binds reaches an open field from the reducer down;
/// with no field open it is nothing, and an unbound one never reaches a view
/// as its letter.
#[test]
fn an_open_field_claims_its_chords_at_the_gate() {
    let now = Instant::now();
    let mut app = App::new(Theme::default_dark());
    app.chrome.active = ViewId::Searches;
    app.reduce(key_action(KeyCode::Tab), now);
    for c in "big buck".chars() {
        app.reduce(key_action(KeyCode::Char(c)), now);
    }
    app.reduce(chord(KeyCode::Char('p'), KeyModifiers::CONTROL), now);
    assert_eq!(app.views.searches.query_text(), "big buck");
    app.reduce(chord(KeyCode::Char('w'), KeyModifiers::CONTROL), now);
    assert_eq!(app.views.searches.query_text(), "big ");
    app.reduce(key_action(KeyCode::Esc), now);
    app.reduce(chord(KeyCode::Char('u'), KeyModifiers::CONTROL), now);
    assert_eq!(app.views.searches.query_text(), "big ", "no field open");
}

/// Ctrl-D and Ctrl-U page a list outside a field, and never reach a view as
/// the letter it binds: `u` brings a closed search back.
#[test]
fn ctrl_d_and_ctrl_u_page_and_reach_no_view_as_their_letter() {
    let now = Instant::now();
    let mut app = App::new(Theme::default_dark());
    app.state = crate::fixture::three_downloads();
    app.chrome.active = ViewId::Transfers;
    let down = chord(KeyCode::Char('d'), KeyModifiers::CONTROL);
    let at = |app: &mut App| app.views.transfers.selected_row();
    app.reduce(down, now);
    assert_eq!(at(&mut app), Some(1));
    app.reduce(chord(KeyCode::Char('u'), KeyModifiers::CONTROL), now);
    assert_eq!(at(&mut app), Some(0));
}

/// A node serving a queue, or with a download waiting for a source, is under
/// way as much as one moving bytes: one `q` must not throw that away.
#[test]
fn a_quit_over_a_queue_or_a_waiting_download_asks_first() {
    let now = Instant::now();
    let peer = |state| crate::state::UploadPeer {
        peer: crate::fixture::peer_endpoint(1),
        state,
        software: None,
    };
    let file = crate::fixture::file_hash(1);
    for under_way in [
        crate::state::UploadState::Uploading { file },
        crate::state::UploadState::Queued { rank: 3, file },
    ] {
        let mut app = App::new(Theme::default_dark());
        let row = peer(under_way);
        app.state.upload_peers.insert(row.peer, row);
        assert!(matches!(
            app.reduce(key_action(KeyCode::Char('q')), now),
            Flow::Continue
        ));
        assert!(app.chrome.quit_open);
    }
    let mut app = App::new(Theme::default_dark());
    app.state = crate::fixture::three_downloads();
    for row in app.state.downloads.values_mut() {
        row.status = crate::state::DownloadStatus::Waiting;
    }
    assert!(matches!(
        app.reduce(key_action(KeyCode::Char('q')), now),
        Flow::Continue
    ));
    let mut app = App::new(Theme::default_dark());
    app.state = crate::fixture::three_downloads();
    for row in app.state.downloads.values_mut() {
        row.status = crate::state::DownloadStatus::Paused;
    }
    assert!(
        matches!(app.reduce(key_action(KeyCode::Char('q')), now), Flow::Quit),
        "paused downloads are at rest"
    );
}

#[test]
fn a_quit_over_a_running_download_asks_first() {
    let now = Instant::now();
    let mut app = App::new(Theme::default_dark());
    assert!(
        matches!(app.reduce(key_action(KeyCode::Char('q')), now), Flow::Quit),
        "nothing running, nothing to ask"
    );
    app.state = crate::fixture::three_downloads();
    assert!(matches!(
        app.reduce(key_action(KeyCode::Char('q')), now),
        Flow::Continue
    ));
    assert!(app.chrome.quit_open);
    app.reduce(key_action(KeyCode::Char('2')), now);
    assert_eq!(app.chrome.active, ViewId::Networks, "the confirm is modal");
    app.reduce(key_action(KeyCode::Esc), now);
    assert!(!app.chrome.quit_open);
    app.reduce(key_action(KeyCode::Char('q')), now);
    assert!(matches!(
        app.reduce(key_action(KeyCode::Char('y')), now),
        Flow::Quit
    ));
    let ctrl_c = || chord(KeyCode::Char('c'), KeyModifiers::CONTROL);
    let mut app = App::new(Theme::default_dark());
    app.state = crate::fixture::three_downloads();
    assert!(matches!(app.reduce(ctrl_c(), now), Flow::Continue));
    assert!(matches!(app.reduce(ctrl_c(), now), Flow::Quit));
}

/// A first press of `2` then a typed word must search, not quit on its `q`.
#[test]
fn arriving_on_searches_with_no_results_focuses_the_query() {
    let now = Instant::now();
    let mut app = App::new(Theme::default_dark());
    app.reduce(key_action(KeyCode::Char('2')), now);
    for letter in "queen".chars() {
        assert!(matches!(
            app.reduce(key_action(KeyCode::Char(letter)), now),
            Flow::Continue
        ));
    }
    assert_eq!(app.views.searches.query_text(), "queen");
}

/// A paste is one thing: its letters run as no key, and its line break sends
/// nothing, wherever it lands.
#[test]
fn a_paste_is_text_or_nothing_and_never_keys() {
    let now = Instant::now();
    let mut app = App::new(Theme::default_dark());
    app.reduce(key_action(KeyCode::Char('2')), now);
    app.reduce(Action::Input(Event::Paste("queen\nlive".into())), now);
    assert_eq!(app.views.searches.query_text(), "queen live");
    assert!(app.pending_commands.is_empty(), "no search went out");
    app.chrome.active = ViewId::SharedFiles;
    assert!(matches!(
        app.reduce(Action::Input(Event::Paste("q2x".into())), now),
        Flow::Continue
    ));
    assert_eq!(app.chrome.active, ViewId::SharedFiles);
}

/// `h` / `l` pass through the tab on the way to another.
#[test]
fn cycling_through_searches_leaves_the_query_alone() {
    let now = Instant::now();
    let mut app = App::new(Theme::default_dark());
    app.reduce(key_action(KeyCode::Char('l')), now);
    app.reduce(key_action(KeyCode::Char('l')), now);
    assert_eq!(app.chrome.active, ViewId::Transfers);
    assert_eq!(app.views.searches.query_text(), "");
}

#[test]
fn input_routes_through_mapping_into_chrome_state() {
    let mut app = App::new(Theme::default_dark());
    let now = Instant::now();
    assert!(matches!(
        app.reduce(key_action(KeyCode::Char('2')), now),
        Flow::Continue
    ));
    assert_eq!(app.chrome.active, ViewId::Searches);
    assert!(app.dirty);
}

/// Statistics is display-only: the digit reaches it, and because
/// it claims no keys the globals keep working on top of it.
#[test]
fn the_fifth_tab_reaches_a_view_that_claims_no_keys() {
    let mut app = App::new(Theme::default_dark());
    let now = Instant::now();
    app.reduce(key_action(KeyCode::Char('5')), now);
    assert_eq!(app.chrome.active, ViewId::Statistics);
    app.reduce(key_action(KeyCode::Char('l')), now);
    assert_eq!(app.chrome.active, ViewId::Settings, "cycle steps past it");
    app.reduce(key_action(KeyCode::Char('l')), now);
    assert_eq!(app.chrome.active, ViewId::Networks, "…and wraps");
    // A click inside the view is nobody's, so it is not swallowed either.
    assert!(matches!(
        app.views
            .view_mut(ViewId::Statistics)
            .handle_click(10, 5, &app.state),
        ViewOutcome::Ignored
    ));
}

/// One key, one meaning (ADR-0073): `[` / `]` move between a tab's own
/// sub-entries — the Held Searches, the only ones any tab has — and never
/// switch tabs. With nothing held, and on every other tab, they do nothing.
#[test]
fn brackets_move_between_held_searches_and_never_switch_tabs() {
    let now = Instant::now();
    let brackets = [KeyCode::Char('['), KeyCode::Char(']')];
    let mut app = App::new(Theme::default_dark());
    for view in ViewId::ALL {
        app.chrome.active = view;
        for code in brackets {
            app.reduce(key_action(code), now);
            assert_eq!(
                app.chrome.active, view,
                "{code:?} on {view:?}, nothing held"
            );
        }
    }

    app.state.session = crate::fixture::session_state().session;
    app.chrome.active = ViewId::Searches;
    for query in ["alpha", "beta"] {
        app.reduce(key_action(KeyCode::Char('/')), now);
        for _ in 0..5 {
            app.reduce(key_action(KeyCode::Backspace), now);
        }
        for c in query.chars() {
            app.reduce(key_action(KeyCode::Char(c)), now);
        }
        app.reduce(key_action(KeyCode::Enter), now);
        app.reduce(key_action(KeyCode::Esc), now);
    }
    assert_eq!(app.views.searches.shown_query(), "beta");
    app.reduce(key_action(KeyCode::Char('[')), now);
    assert_eq!(app.views.searches.shown_query(), "alpha");
    app.reduce(key_action(KeyCode::Char(']')), now);
    assert_eq!(app.views.searches.shown_query(), "beta");
    assert_eq!(app.chrome.active, ViewId::Searches);

    for view in ViewId::ALL.into_iter().filter(|v| *v != ViewId::Searches) {
        app.chrome.active = view;
        for code in brackets {
            app.reduce(key_action(code), now);
            assert_eq!(app.chrome.active, view, "{code:?} on {view:?}, two held");
        }
    }
    assert_eq!(
        app.views.searches.shown_query(),
        "beta",
        "held elsewhere, untouched"
    );
}

#[test]
fn quit_flows_out_of_reduce() {
    let mut app = App::new(Theme::default_dark());
    assert!(matches!(
        app.reduce(key_action(KeyCode::Char('q')), Instant::now()),
        Flow::Quit
    ));
    // …but not while help is open: there it is typed into the filter.
    let mut app = App::new(Theme::default_dark());
    app.reduce(key_action(KeyCode::Char('?')), Instant::now());
    assert!(app.chrome.help_open);
    assert!(matches!(
        app.reduce(key_action(KeyCode::Char('q')), Instant::now()),
        Flow::Continue
    ));
    assert!(app.chrome.help_open);
    assert!(app.chrome.help_typed());
}

#[test]
fn resize_marks_dirty_without_an_action() {
    let mut app = App::new(Theme::default_dark());
    app.dirty = false;
    app.reduce(Action::Input(Event::Resize(120, 40)), Instant::now());
    assert!(app.dirty);
}

/// A restart of a failed download that fails again leaves the row as it
/// was, so the status bar names the download and why, at once — the fault's
/// part and hashes included — while a first failure flashes nothing.
#[test]
fn a_restart_that_fails_again_says_so_on_the_status_bar() {
    use rmule_core::{
        CoreEvent, DownloadEvent, DownloadFailure, DownloadId, DownloadLifecycle, DownloadMetadata,
        DownloadMetadataOrigin, PartFault, StorageIntegrityFault,
    };
    use rmule_primitives::{Ed2kText, FileHash, PartHash};

    let mut app = App::new(Theme::default_dark());
    let now = Instant::now();
    let id = DownloadId::from_u64(4);
    let failed = |reason: DownloadFailure| {
        Action::Core(CoreEvent::Download(DownloadEvent::DownloadFailed {
            download_id: id,
            reason,
        }))
    };
    app.reduce(
        Action::Core(CoreEvent::Download(DownloadEvent::DownloadRecovered {
            download_id: id,
            state: DownloadLifecycle::Paused,
            failure: None,
            file_hash: FileHash::from_bytes([0xA0; FileHash::BYTE_LEN]),
            metadata: DownloadMetadata {
                name: Ed2kText::from_utf8("archive.rar"),
                size: 30_000_000,
                origin: DownloadMetadataOrigin::Link,
            },
            file_path: crate::fixture::part_file(),
        })),
        now,
    );
    let fault = StorageIntegrityFault::NoPartHolds {
        recorded: 49,
        first: PartFault::HashMismatch {
            part_index: 0,
            expected: PartHash::from_bytes([0x11; PartHash::BYTE_LEN]),
            found: PartHash::from_bytes([0x22; PartHash::BYTE_LEN]),
        },
    };
    app.reduce(
        failed(DownloadFailure::StorageIntegrityFailed(fault.clone())),
        now,
    );
    assert_eq!(
        app.chrome.flash_text(now),
        None,
        "a first failure is the notable line"
    );

    app.reduce(failed(DownloadFailure::StorageIntegrityFailed(fault)), now);
    let flash = app
        .chrome
        .flash_text(now)
        .expect("the failed restart flashes");
    assert!(
        flash.starts_with("archive.rar: restart failed again: "),
        "{flash}"
    );
    assert!(
        flash.contains("none of its 49 checked parts still matches (part 0 hashes to 2222"),
        "{flash}"
    );
    assert!(flash.contains("it was checked as 1111"), "{flash}");
}

/// The status bar names quit's step from the core's own
/// `Quitting` event, not from a stop the front end issued.
#[test]
fn a_quit_step_the_core_announces_names_itself_on_the_status_bar() {
    let mut app = App::new(Theme::default_dark());
    let now = Instant::now();
    app.reduce(
        Action::Core(rmule_core::CoreEvent::Quitting {
            step: rmule_core::QuitStep::Kad,
        }),
        now,
    );
    assert_eq!(app.chrome.flash_text(now), Some("Shutting down… Kad"));
    assert!(app.dirty, "the step is drawn");
}

#[test]
fn copy_link_queues_the_osc52_write_and_flashes() {
    let mut app = App::new(Theme::default_dark());
    app.reduce(
        Action::CopyLink("ed2k://|file|x|1|AA|/".into()),
        Instant::now(),
    );
    assert_eq!(app.pending_copy.as_deref(), Some("ed2k://|file|x|1|AA|/"));
    assert_eq!(
        app.chrome.flash_text(Instant::now()),
        Some("link sent to the terminal's clipboard"),
        "the flash claims the write, not the clipboard"
    );
    assert_eq!(
        app.state.notable.as_ref().map(|note| note.as_str()),
        Some("link: ed2k://|file|x|1|AA|/"),
        "a terminal that ignored the write leaves the link readable"
    );
}

#[test]
fn wheel_scroll_reaches_the_focused_table_as_arrows() {
    use ratatui::crossterm::event::{MouseButton, MouseEvent, MouseEventKind};
    let mut app = App::new(Theme::default_dark());
    // Two rows so selection can move.
    for n in [1, 2] {
        app.state.apply(
            Action::Core(rmule_core::CoreEvent::Download(
                rmule_core::DownloadEvent::DownloadQueued {
                    download_id: rmule_core::DownloadId::from_u64(n),
                    file_hash: rmule_primitives::FileHash::from_bytes([n as u8; 16]),
                    metadata: rmule_core::DownloadMetadata::unnamed(0),
                    file_path: crate::fixture::part_file(),
                },
            )),
            Instant::now(),
        );
    }
    // The downloads table is Transfers'.
    app.reduce(key_action(KeyCode::Char('3')), Instant::now());
    app.dirty = false;
    let wheel = |kind| {
        Action::Input(Event::Mouse(MouseEvent {
            kind,
            column: 10,
            row: 5,
            modifiers: ratatui::crossterm::event::KeyModifiers::NONE,
        }))
    };
    app.reduce(wheel(MouseEventKind::ScrollDown), Instant::now());
    assert!(app.dirty, "wheel must scroll the focused table");
    // A plain click outside row 0 is the view's, not the chrome's.
    app.dirty = false;
    app.reduce(
        wheel(MouseEventKind::Down(MouseButton::Left)),
        Instant::now(),
    );
    assert!(!app.dirty);
}

/// The start-lane sequencing, from the app's side: the run's first eD2k *login*
/// starts the Kad join, and nothing else in the connection trail does —
/// neither the dial that precedes it nor the reconnect that follows. The
/// operator's `K` starts it again after a stop, and a Kad the operator
/// stopped before any login is not started by the login.
#[test]
fn the_first_server_login_starts_the_kad_join_once_and_k_starts_it_again() {
    use rmule_core::ServerConnectionEvent as Connection;
    use tokio::sync::mpsc::error::TryRecvError;

    let server = || rmule_primitives::ServerEndpoint::new("10.0.0.1", 4661).expect("endpoint");
    let connection = |event| Action::Core(rmule_core::CoreEvent::ServerConnection(event));
    let login = || Connection::Connected {
        server: server(),
        client_id: rmule_primitives::ClientId::from_u32(0x0A00_0007),
    };

    let (start, mut starts) = crate::kad::start_lane();
    let mut app = App::new(Theme::default_dark()).with_kad_start(start);
    let now = Instant::now();

    app.reduce(
        connection(Connection::Connecting {
            server: server(),
            leaving: None,
        }),
        now,
    );
    assert_eq!(
        starts.try_recv(),
        Err(TryRecvError::Empty),
        "a dial that may still fail must not start a Kad node"
    );

    app.reduce(connection(login()), now);
    assert_eq!(starts.try_recv(), Ok(()), "the first login starts the join");

    // The trail a server switch produces, replayed in full: the first-login
    // start is spent, so the second login changes nothing.
    app.reduce(
        connection(Connection::Disconnected { server: server() }),
        now,
    );
    app.reduce(connection(login()), now);
    assert_eq!(
        starts.try_recv(),
        Err(TryRecvError::Empty),
        "one first-login start per run — a re-login must not re-fetch or re-join"
    );

    app.reduce(Action::StartKad, now);
    assert_eq!(starts.try_recv(), Ok(()), "K starts it again");

    // Stopped before any login: the login leaves it stopped.
    let (start, mut starts) = crate::kad::start_lane();
    let mut app = App::new(Theme::default_dark()).with_kad_start(start);
    app.reduce(Action::Command(rmule_core::CoreCommand::DisableKad), now);
    app.reduce(connection(login()), now);
    assert_eq!(starts.try_recv(), Err(TryRecvError::Empty));
}

/// The join task ends when the core stops. A start sent to it after that
/// reaches nothing, and the operator is told why, once — by `K` and by the
/// first login alike.
#[test]
fn a_start_of_kad_after_the_join_ended_says_so_once() {
    use rmule_core::ServerConnectionEvent as Connection;

    let login = || {
        Action::Core(rmule_core::CoreEvent::ServerConnection(
            Connection::Connected {
                server: rmule_primitives::ServerEndpoint::new("10.0.0.1", 4661).expect("endpoint"),
                client_id: rmule_primitives::ClientId::from_u32(0x0A00_0007),
            },
        ))
    };
    let now = Instant::now();

    let (start, starts) = crate::kad::start_lane();
    drop(starts);
    let mut app = App::new(Theme::default_dark()).with_kad_start(start);
    app.reduce(Action::StartKad, now);
    assert_eq!(
        app.state.notable.as_deref(),
        Some(crate::words::kad::JOIN_ENDED.as_str())
    );
    app.state.notable = None;
    app.reduce(Action::StartKad, now);
    assert_eq!(app.state.notable, None, "told once");

    let (start, starts) = crate::kad::start_lane();
    drop(starts);
    let mut app = App::new(Theme::default_dark()).with_kad_start(start);
    app.reduce(login(), now);
    assert_eq!(
        app.state.notable.as_deref(),
        Some(crate::words::kad::JOIN_ENDED.as_str()),
        "the login's own start is told too"
    );
}

/// The Settings write-through, end to end: the store keeps it, the
/// snapshot the tab renders folds it, the *live* half is applied here and
/// now, and the receipt names the restart when there is one.
#[test]
fn a_settings_edit_reaches_the_store_and_the_live_half_lands_at_once() {
    use crate::config::{PrefEdit, SharedConfig, ThemeChoice};

    let store = rmule_testkit::memory_store();
    let config = SharedConfig::open(store);
    let preferences = config.load(None).expect("load");

    let mut app = App::new(Theme::default_dark())
        .with_session(crate::state::SessionConfig {
            server: None,
            download_dir: None,
        })
        .with_config(config.clone(), preferences);
    let now = Instant::now();

    app.reduce(Action::Preference(PrefEdit::Theme(ThemeChoice::Light)), now);
    assert_eq!(app.theme.bg, Theme::light().bg, "the palette swaps at once");
    assert_eq!(app.state.preferences.theme, ThemeChoice::Light);

    let dir = rmule_testkit::absolute_path("tmp/rmule-dl");
    app.reduce(Action::Preference(PrefEdit::download_dir(dir.clone())), now);
    assert_eq!(
        app.state.session.download_dir.clone(),
        Some(dir.clone()),
        "the next download reads the new directory, not the startup one"
    );

    app.reduce(
        Action::Preference(PrefEdit::Core(Setting::TcpPort(4711))),
        now,
    );
    assert_eq!(
        app.chrome.flash_text(now),
        Some("saved: eD2k port → 4711 (takes effect on restart)")
    );

    // …and all three are on disk, not just in the UI.
    let reloaded = config.load(None).expect("reload");
    assert_eq!(reloaded.theme, ThemeChoice::Light);
    assert_eq!(reloaded.core.download_dir, Some(dir));
}

/// Two tables keep two different sorts in the one stored preference, and
/// a restart hands each its own back.
#[test]
fn two_tables_keep_their_own_sorts_across_a_restart() {
    use crate::config::SharedConfig;
    use crate::fixture::{listed_servers, three_downloads};
    use crate::table_sort::Direction;

    let config = SharedConfig::open(rmule_testkit::memory_store());
    let with_rows = |app: &mut App| {
        app.state.downloads = three_downloads().downloads;
        app.state.diagnostics = three_downloads().diagnostics;
        app.state.diagnostics.servers = listed_servers().diagnostics.servers;
    };
    let mut app = App::new(Theme::default_dark())
        .with_config(config.clone(), config.load(None).expect("load"));
    with_rows(&mut app);
    let now = Instant::now();
    // Transfers by speed, the column after its opening one; its sources
    // pane, focused, by software; the servers by address, reversed.
    for key in [
        KeyCode::Char('3'),
        KeyCode::Char('s'),
        KeyCode::Tab,
        KeyCode::Char('s'),
        KeyCode::Char('1'),
        KeyCode::Char('s'),
        KeyCode::Char('S'),
    ] {
        app.reduce(key_action(key), now);
    }

    let reloaded = config.load(None).expect("reload");
    assert_eq!(
        reloaded.table_sorts.get("transfers"),
        Some(("speed", Direction::Descending))
    );
    assert_eq!(
        reloaded.table_sorts.get("servers"),
        Some(("address", Direction::Descending))
    );
    assert_eq!(
        reloaded.table_sorts.get("sources"),
        Some(("software", Direction::Ascending))
    );
    assert_eq!(reloaded.table_sorts.get("shared"), None, "untouched");

    let mut restarted = App::new(Theme::default_dark()).with_config(config, reloaded);
    with_rows(&mut restarted);
    let header = |app: &mut App, view: ViewId| {
        let screen = crate::golden::render_to_lines(78, 21, |frame| {
            app.views
                .view_mut(view)
                .draw(frame, frame.area(), &app.state, &app.theme, now);
        });
        screen.lines().nth(1).unwrap_or_default().to_string()
    };
    assert!(header(&mut restarted, ViewId::Transfers).contains("Speed ▼"));
    let screen = crate::golden::render_to_lines(78, 21, |frame| {
        restarted.views.view_mut(ViewId::Transfers).draw(
            frame,
            frame.area(),
            &restarted.state,
            &restarted.theme,
            now,
        );
    });
    assert!(screen.contains("Software ▲"), "{screen}");
    let servers = header(&mut restarted, ViewId::Networks);
    assert!(servers.contains("Address ▼") && !servers.contains("Name ▲"));
}

/// A value Core Settings refuses is told by why it was refused, not as a
/// store failure, and nothing is applied.
#[test]
fn a_refused_value_says_why() {
    use crate::config::SharedConfig;

    let config = SharedConfig::open(rmule_testkit::memory_store());
    let preferences = config.load(None).expect("load");
    let mut app = App::new(Theme::default_dark()).with_config(config, preferences);
    let now = Instant::now();
    let limit = app.state.preferences.core.server_policy.dead_after;

    app.reduce(
        Action::Preference(crate::config::PrefEdit::Core(Setting::DeadServerRetries(0))),
        now,
    );
    assert_eq!(
        app.chrome.flash_text(now),
        Some("not saved: the dead server limit must be at least 1")
    );
    assert_eq!(app.state.preferences.core.server_policy.dead_after, limit);
}

/// A download dir the share guards refuse is told by the guard's reason, and
/// the next download still reads the directory it read before.
#[test]
fn a_download_dir_the_share_guards_refuse_says_why_and_is_not_applied() {
    use crate::config::SharedConfig;

    let store = rmule_testkit::memory_store();
    let home = tempfile::tempdir().expect("a home");
    let handle =
        rmule_core::CoreSettingsHandle::open(store.clone()).share_guards(rmule_core::ShareGuards {
            home: Some(home.path().to_path_buf()),
            data_dir: None,
        });
    let config = SharedConfig::new(handle, rmule_core::DurableAppConfig::new(store));
    let preferences = config.load(None).expect("load");
    let before = rmule_testkit::absolute_path("srv/rmule-dl");
    let mut app = App::new(Theme::default_dark())
        .with_session(crate::state::SessionConfig {
            server: None,
            download_dir: Some(before.clone()),
        })
        .with_config(config, preferences);
    let now = Instant::now();

    app.reduce(
        Action::Preference(crate::config::PrefEdit::download_dir(
            home.path().to_path_buf(),
        )),
        now,
    );
    assert_eq!(
        app.chrome.flash_text(now),
        Some(
            "not saved: everything under the download dir is shared, and it is your home directory"
        )
    );
    assert_eq!(app.state.session.download_dir, Some(before));
}

/// A download directory the share guards refuse is refused as the form
/// asks to confirm it, before the warning that everything under it would be
/// offered (ADR-0101); one they pass gets the warning.
#[test]
fn a_refused_download_dir_is_said_before_the_share_warning() {
    use crate::config::SharedConfig;

    let store = rmule_testkit::memory_store();
    let home = tempfile::tempdir().expect("a home");
    let handle =
        rmule_core::CoreSettingsHandle::open(store.clone()).share_guards(rmule_core::ShareGuards {
            home: Some(home.path().to_path_buf()),
            data_dir: None,
        });
    let config = SharedConfig::new(handle, rmule_core::DurableAppConfig::new(store));
    let preferences = config.load(None).expect("load");
    let mut app = App::new(Theme::default_dark()).with_config(config, preferences);
    let now = Instant::now();

    app.reduce(Action::ConfirmDownloadDir(home.path().to_path_buf()), now);
    assert_eq!(
        app.views.settings.refusal(),
        Some(
            "not saved: everything under the download dir is shared, and it is your home directory"
        ),
        "the refusal stays under the field"
    );
    assert_eq!(app.views.settings.warned_dir(), None, "no share warning");

    let elsewhere = tempfile::tempdir().expect("a directory");
    app.reduce(
        Action::ConfirmDownloadDir(elsewhere.path().to_path_buf()),
        now,
    );
    assert_eq!(app.views.settings.warned_dir(), Some(elsewhere.path()));
}

/// The bar may shorten a flash and drops it in seconds: the log keeps it whole.
#[test]
fn a_flash_stays_in_the_log_whole() {
    let mut app = App::new(Theme::default_dark());
    let now = Instant::now();
    app.reduce(Action::Flash(crate::fixture::LONG_FLASH), now);
    assert_eq!(
        app.state.log.back().map(|line| &line.text),
        Some(&crate::fixture::LONG_FLASH)
    );
}

/// The next run opens on the tab this one left up, however it got there.
#[test]
fn the_tab_left_up_is_the_tab_the_next_run_opens_on() {
    use crate::config::SharedConfig;

    let config = SharedConfig::open(rmule_testkit::memory_store());
    let preferences = config.load(None).expect("load");
    let mut app = App::new(Theme::default_dark()).with_config(config.clone(), preferences);
    let now = Instant::now();
    app.reduce(Action::SwitchView(ViewId::Transfers), now);
    app.reduce(Action::CycleView(1), now);

    let reopened = config.load(None).expect("load");
    let app = App::new(Theme::default_dark()).with_config(config, reopened);
    assert_eq!(app.chrome.active, ViewId::SharedFiles);
}

/// The bell is opt-in, and rings for the completing edge.
#[test]
fn a_finished_download_rings_only_when_the_operator_asked() {
    let completed = || {
        Action::Core(rmule_core::CoreEvent::Download(
            rmule_core::DownloadEvent::DownloadCompleted {
                download_id: crate::fixture::download_id(1),
                final_path: crate::fixture::part_file(),
            },
        ))
    };
    let mut app = App::new(Theme::default_dark());
    let now = Instant::now();
    app.reduce(completed(), now);
    assert!(!app.pending_bell, "off by default");

    app.state
        .preferences
        .flags
        .set(AppFlag::CompletionBell, true);
    app.reduce(completed(), now);
    assert!(app.pending_bell);
}

/// The server a connect at start dials is kept on each login; when the store
/// refuses the write the operator is told once, not on every login.
#[test]
fn a_refused_write_of_the_last_server_is_told_once() {
    use crate::config::SharedConfig;

    let config = SharedConfig::open(rmule_testkit::memory_store());
    let preferences = config.load(None).expect("load");
    config.refuse_commits();
    let mut app = App::new(Theme::default_dark()).with_config(config, preferences);
    let now = Instant::now();
    let server = rmule_primitives::ServerEndpoint::new("srv.example", 4661).expect("endpoint");
    let connected = || {
        Action::Core(rmule_core::CoreEvent::ServerConnection(
            rmule_core::ServerConnectionEvent::Connected {
                server: server.clone(),
                client_id: rmule_primitives::ClientId::from_u32(0x0100_0000),
            },
        ))
    };

    app.reduce(connected(), now);
    assert_eq!(
        app.state.notable.as_deref(),
        Some("could not remember this server: connect at start may dial another (see the run log)")
    );
    assert_eq!(app.state.preferences.last_server, None);

    app.state.notable = None;
    app.reduce(connected(), now);
    assert_ne!(
        app.state.notable.as_deref(),
        Some(crate::words::store::LAST_SERVER_NOT_SAVED.as_str()),
        "not told twice"
    );
}

/// The Settings row for the Run Log's level is live: the handle the writers
/// read changes with the edit, before any restart.
#[test]
fn the_full_run_log_preference_changes_the_level_the_writers_read() {
    use crate::config::{PrefEdit, SharedConfig};
    use rmule_core::run_log::{Level, LevelHandle};

    let config = SharedConfig::open(rmule_testkit::memory_store());
    let preferences = config.load(None).expect("load");
    let writers = LevelHandle::default();
    let mut app = App::new(Theme::default_dark())
        .with_run_log(writers.clone())
        .with_config(config, preferences);
    let now = Instant::now();
    assert_eq!(writers.get(), Level::Lean);

    app.reduce(
        Action::Preference(PrefEdit::Flag(AppFlag::RunLogFull, true)),
        now,
    );
    assert_eq!(writers.get(), Level::Full);

    app.reduce(
        Action::Preference(PrefEdit::Flag(AppFlag::RunLogFull, false)),
        now,
    );
    assert_eq!(writers.get(), Level::Lean);
}

/// `c` is Networks' key for its selected row and unbound on every other tab:
/// no view claims it and no global catches it, even with a connected server
/// that a fallback would hang up.
#[test]
fn c_outside_networks_is_unbound() {
    let mut app = App::new(Theme::default_dark());
    app.state = crate::fixture::listed_servers();
    let key = crate::fixture::press(KeyCode::Char('c'));
    for view in ViewId::ALL.into_iter().filter(|v| *v != ViewId::Networks) {
        app.chrome.active = view;
        assert!(
            matches!(
                app.views.view_mut(view).handle_key(key, &app.state),
                ViewOutcome::Ignored
            ),
            "{view:?} claims `c`"
        );
        assert!(
            crate::input::map_key(&app.chrome, key).is_none(),
            "`c` is global"
        );
    }
}

/// Under the too-small screen no view is on show, so a key reaches none of
/// them, and `q` still leaves.
#[test]
fn a_terminal_too_small_answers_only_the_way_out() {
    let now = Instant::now();
    let mut app = App::new(Theme::default_dark());
    app.too_small = true;
    let before = app.chrome.active;
    assert!(matches!(
        app.reduce(key_action(KeyCode::Char('l')), now),
        Flow::Continue
    ));
    assert_eq!(app.chrome.active, before, "the tab keys are not heard");
    assert!(matches!(
        app.reduce(key_action(KeyCode::Char('q')), now),
        Flow::Quit
    ));
}
