//! The UI loop (ADR-0069 §Runtime/§Dataflow): one `select!` over the action
//! bus (input pump + bridge share it) and the render tick. Dirty-flag
//! coalescing capped at ~30 fps; input events redraw immediately; bursts of
//! core events between frames collapse into one draw of the latest state.
//!
//! Quit hands the bridge's owned `Core` through its own **Quit**:
//! the core stops every activity in order and flushes, bounded so a
//! stuck core cannot hang the terminal. The front end issues no stops of its
//! own; the status bar names each step the core announces as it runs it
//! See `App::graceful_quit`.
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;

use crate::action::Action;
use crate::bridge::BridgeHandle;
use crate::chrome::{self, ChromeState};
use crate::client::CoreClient;
use crate::state::UiState;
use crate::stop::Stop;
use crate::theme::Theme;
use crate::tui::{Drawn, Surface};
use views::Views;

mod history;
mod preview;
mod reduce;
mod related;
mod views;

/// Render coalescing cap (spec §2: ≤30 fps).
const RENDER_INTERVAL: Duration = Duration::from_millis(33);

/// The running UI: everything a frame is drawn from, plus the work the
/// synchronous reducer cannot do itself (terminal writes, core sends) parked
/// for the loop to flush.
pub struct App {
    /// What core has said so far — the reducer's one input besides the action.
    pub state: UiState,
    /// Which view is up, the help overlay, the flash: state core never sees.
    pub chrome: ChromeState,
    views: Views,
    theme: Theme,
    /// What the *environment* resolved to (spec §5), kept so the Settings
    /// tab's `auto` theme choice has something to mean at runtime.
    auto_theme: Theme,
    /// The config store the Settings tab writes through; `None` until
    /// [`with_config`](Self::with_config).
    config: Option<crate::config::SharedConfig>,
    dirty: bool,
    /// The terminal as last drawn is under the minimum: the too-small screen
    /// is up, and only the way out answers.
    too_small: bool,
    /// A link waiting for the OSC 52 write (needs the terminal, which
    /// `reduce` never sees); flushed by the run loop.
    pending_copy: Option<String>,
    /// A finished download owes the terminal's bell; flushed by the run loop.
    pending_bell: bool,
    /// The title the terminal shows now, so a frame writes only a change.
    shown_title: Option<String>,
    /// The command door to the core; `None` until
    /// [`with_client`](Self::with_client).
    client: Option<BridgeHandle>,
    /// Commands awaiting the async send (reduce is sync); flushed by the
    /// run loop in order.
    pending_commands: Vec<rmule_core::CoreCommand>,
    /// The Kad join's start lane: sent on the run's first eD2k
    /// login, and on the operator's `K`. `None` until
    /// [`with_kad_start`](Self::with_kad_start).
    kad_start: Option<crate::kad::KadStarter>,
    /// The player lane: each Preview sends one launch on it. `None` until
    /// [`with_player`](Self::with_player).
    player: Option<crate::player::PlayerLauncher>,
    /// Whether the first-login start is still owed: spent by that login, or
    /// by the operator's own `K` first, so a login never re-starts a Kad the
    /// operator stopped.
    kad_first_login_owed: bool,
    /// Whether the operator was told the Kad join has ended and Kad cannot be
    /// started; told once.
    kad_join_ended_told: bool,
    /// Whether the operator was told the last-connected server could not be
    /// kept; told once, however many logins follow.
    last_server_unsaved_told: bool,
    /// Likewise for the tab the next run opens on.
    last_tab_unsaved_told: bool,
    /// The Run Log's level, shared with its writers: the Settings row turns
    /// it, and the next line written follows.
    run_log: rmule_core::run_log::LevelHandle,
    /// The File History's ask, kept to one out at a time.
    history: history::HistoryPoll,
    /// What ends the loop from outside it; a test's arms no deadline.
    stop: Stop,
    /// A key or signal's work on the terminal (which `reduce` never sees);
    /// done by the run loop.
    pending_terminal: Option<TerminalWork>,
}

/// What one action did to the loop.
enum Flow {
    Continue,
    Quit,
}

impl App {
    /// An app with nothing attached yet: `main` gives it each with a `with_*`
    /// below before the run starts, and a run that cannot get them never
    /// reaches here (ADR-0083).
    #[must_use]
    pub fn new(theme: Theme) -> Self {
        Self {
            state: UiState::default(),
            chrome: ChromeState::default(),
            views: Views::default(),
            theme,
            auto_theme: theme,
            config: None,
            dirty: true, // first frame always paints
            too_small: false,
            pending_copy: None,
            pending_bell: false,
            shown_title: None,
            client: None,
            pending_commands: Vec::new(),
            kad_start: None,
            player: None,
            kad_first_login_owed: false,
            kad_join_ended_told: false,
            last_server_unsaved_told: false,
            last_tab_unsaved_told: false,
            run_log: rmule_core::run_log::LevelHandle::default(),
            history: history::HistoryPoll::default(),
            stop: Stop::default(),
            pending_terminal: None,
        }
    }

    /// Bind the in-process core client: view-emitted commands now
    /// forward instead of flashing "core not attached".
    #[must_use]
    pub fn with_client(mut self, client: BridgeHandle) -> Self {
        self.client = Some(client);
        // The Known-File Marks' durable half, read once the core is there.
        self.pending_commands.extend(self.history.ask());
        self
    }

    /// Install the startup-loaded session config: views construct real
    /// `Start*`/`Resume` commands from it.
    #[must_use]
    pub fn with_session(mut self, session: crate::state::SessionConfig) -> Self {
        self.state.session = session;
        self
    }

    /// Install the config store and the preferences startup read out of it
    /// The Settings tab now writes real edits, and the stored theme
    /// choice takes over from the environment-detected one.
    #[must_use]
    pub fn with_config(
        mut self,
        config: crate::config::SharedConfig,
        preferences: crate::config::Preferences,
    ) -> Self {
        self.theme = preferences.theme.resolve(self.auto_theme);
        self.run_log.set(rmule_core::run_log::Level::from_full(
            preferences.run_log_full,
        ));
        self.views.searches.restore_sort(&preferences.table_sorts);
        self.views.transfers.restore_sort(&preferences.table_sorts);
        self.views.networks.restore_sort(&preferences.table_sorts);
        self.views.shared.restore_sort(&preferences.table_sorts);
        self.chrome.active = preferences.last_tab;
        self.state.preferences = preferences;
        self.config = Some(config);
        self
    }

    /// Share the Run Log's level handle, so the Settings row turns the level
    /// its writers read.
    #[must_use]
    pub fn with_run_log(mut self, level: rmule_core::run_log::LevelHandle) -> Self {
        self.run_log = level;
        self
    }

    /// Install the Kad join's start lane: the join parked on its
    /// other half starts a node when this app observes its first eD2k login,
    /// or when the operator presses `K`, and never at startup.
    #[must_use]
    pub fn with_kad_start(mut self, start: crate::kad::KadStarter) -> Self {
        self.kad_start = Some(start);
        self.kad_first_login_owed = true;
        self
    }

    /// Install the player lane (ADR-0114): each Preview hands its launch to
    /// the task on the lane's other half. Without one a Preview flashes that
    /// no core is attached.
    #[must_use]
    pub fn with_player(mut self, player: crate::player::PlayerLauncher) -> Self {
        self.player = Some(player);
        self
    }

    /// Hand the run its [`Stop`]: what ends the loop from outside it.
    #[must_use]
    pub fn with_stop(mut self, stop: Stop) -> Self {
        self.stop = stop;
        self
    }

    /// Drive the UI until quit, until every action producer is gone or until
    /// a stop is asked for: a signal, or the terminal's loss. Each of those
    /// is a Quit (ADR-0118).
    pub async fn run<S: Surface>(mut self, tui: &mut S, mut actions: mpsc::Receiver<Action>) {
        self.drive(tui, &mut actions).await;
        self.graceful_quit(tui, &mut actions).await;
    }

    /// The loop, until something ends the run. It waits on nothing but these
    /// arms: the terminal's writes are the line's, so a stop always finds it.
    async fn drive<S: Surface>(&mut self, tui: &mut S, actions: &mut mpsc::Receiver<Action>) {
        let mut render = tokio::time::interval(RENDER_INTERVAL);
        render.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut last_frame = None;
        let stop = self.stop.clone();

        loop {
            tokio::select! {
                biased;
                () = stop.requested() => break,
                maybe = actions.recv() => {
                    let Some(action) = maybe else { break };
                    let now = Instant::now();
                    self.state.log.set_wall(now, chrono::Local::now().fixed_offset());
                    let immediate = matches!(action, Action::Input(_));
                    match self.reduce(action, now) {
                        Flow::Quit => break,
                        Flow::Continue => {}
                    }
                    if let Some(link) = self.pending_copy.take() {
                        tui.copy_to_clipboard(&link);
                    }
                    self.terminal_work(tui, now);
                    self.flush_commands();
                    // ADR-0069: input redraws immediately; core bursts wait
                    // for the render tick and collapse into one frame. So
                    // does a burst of input, a wheel or a held key, past the
                    // tick's own rate.
                    let due = last_frame.is_none_or(|at: Instant| at.elapsed() >= RENDER_INTERVAL);
                    if immediate && self.dirty && due {
                        self.draw(tui, now);
                        last_frame = Some(now);
                    }
                }
                _ = render.tick() => {
                    let now = Instant::now();
                    // A flash or a note ageing out is a repaint nothing asked for.
                    if self.chrome.expire_flash(now) | self.state.expire_note(now) {
                        self.dirty = true;
                    }
                    if self.dirty {
                        self.draw(tui, now);
                        last_frame = Some(now);
                    }
                }
            }
        }
    }

    /// Do what a key or a signal parked for the terminal.
    fn terminal_work<S: Surface>(&mut self, tui: &mut S, now: Instant) {
        if std::mem::take(&mut self.pending_bell) {
            tui.ring_bell();
        }
        match self.pending_terminal.take() {
            None => {}
            Some(TerminalWork::Repaint) => tui.repaint(),
            Some(TerminalWork::Reenter) => tui.reenter(),
            Some(TerminalWork::Suspend) => {
                if let Err(refused) = tui.suspend() {
                    let _ = self.reduce(Action::Flash(crate::words::app::no_suspend(refused)), now);
                }
            }
        }
    }

    /// The graceful sequence `Flow::Quit` runs before the loop breaks
    /// Hand the bridge's owned `Core` through its own
    /// **Quit** via `BridgeHandle::graceful_shutdown` — every activity's stop
    /// in order, then the credit checkpoint — bounded so a stuck actor cannot
    /// hang the terminal. The front end issues no stop of its own: the core's
    /// quit runs them all (ADR-0093). What the user sees is
    /// driven by the quit itself — one frame with the opening flash before
    /// anything runs, then a redraw naming each step as the core announces
    /// it (`CoreEvent::Quitting`, reduced like any other event). The terminal
    /// is restored only once this returns and the loop breaks. With no client
    /// there is no core to quit, and it returns at once, drawing nothing. A
    /// frame the terminal cannot take stops no step of the quit.
    ///
    /// `actions` is the same bus `App::run` reads — the only door onto
    /// core's events this app has, since the bridge is single-consumer; it
    /// is drained here while quit runs so the bridge's forwarding never
    /// stalls on a full bus.
    async fn graceful_quit<S: Surface>(
        &mut self,
        tui: &mut S,
        actions: &mut mpsc::Receiver<Action>,
    ) {
        self.stop.request();
        let Some(client) = self.client.clone() else {
            return;
        };
        let now = Instant::now();
        self.chrome
            .update(&Action::Flash(crate::words::app::SHUTTING_DOWN), now);
        self.dirty = true;
        self.draw(tui, now);

        let quit = client.graceful_shutdown();
        tokio::pin!(quit);
        loop {
            tokio::select! {
                biased;
                _ = &mut quit => break,
                action = actions.recv() => match action {
                    Some(step) => self.draw_quit_step(tui, step),
                    None => {
                        quit.await;
                        break;
                    }
                },
            }
        }
        // The door answers right after the bridge queues its last steps (the
        // grace-elapsed notice among them), so the arm above can win the
        // race with them still on the bus: draw whatever is queued before
        // the terminal is restored.
        while let Ok(step) = actions.try_recv() {
            self.draw_quit_step(tui, step);
        }
    }

    /// Reduce and draw one bus action during quit if it is the status bar's
    /// receipt for the wait: a quit step is the core's own progress, and a
    /// Flash is the bridge's grace-elapsed notice. Every other action is
    /// dropped — nothing else is drawn while the core is stopping.
    fn draw_quit_step<S: Surface>(&mut self, tui: &mut S, step: Action) {
        if matches!(
            step,
            Action::Core(rmule_core::CoreEvent::Quitting { .. }) | Action::Flash(_)
        ) {
            let now = Instant::now();
            let _ = self.reduce(step, now);
            self.draw(tui, now);
        }
    }

    /// Forward queued commands through the client, in order. A send failing
    /// means the core stopped — `Action::CoreClosed` follows on the bus and
    /// renders the honest state, so failures are not re-flashed here.
    fn flush_commands(&mut self) {
        if self.pending_commands.is_empty() {
            return;
        }
        let Some(client) = self.client.clone() else {
            self.pending_commands.clear();
            return;
        };
        for command in self.pending_commands.drain(..) {
            if client.send(command).is_err() {
                break;
            }
        }
    }

    /// Draw if the terminal can take a frame; if not, the state stays dirty
    /// and the next tick asks again.
    fn draw<S: Surface>(&mut self, tui: &mut S, now: Instant) {
        let state = &self.state;
        let chrome_state = &self.chrome;
        let theme = &self.theme;
        let views = &mut self.views;
        let mut too_small = false;
        let title = chrome::terminal_title(state);
        let new_title = (title != self.shown_title).then_some(title);
        let drawn = tui.draw(|frame| {
            too_small = crate::views::too_small::holds(frame.area());
            let caret = if too_small {
                crate::views::too_small::draw(frame, theme);
                None
            } else {
                let content = chrome::draw_frame(frame, state, chrome_state, theme, now);
                views.draw(chrome_state.active, frame, content, state, theme, now)
            };
            chrome::draw_overlays(frame, state, chrome_state, theme);
            // The terminal's own cursor, where an input method composes.
            // An overlay covers the field and takes the keys.
            if let Some(caret) = caret
                && !chrome_state.help_open
                && !chrome_state.quit_open
            {
                frame.set_cursor_position(caret);
            }
        });
        // A held frame rendered nothing: its size, caret and title all stay
        // owed, and the next tick draws them with the state that holds then.
        if drawn == Drawn::Shown {
            if let Some(title) = new_title {
                tui.set_title(title.as_deref());
                self.shown_title = title;
            }
            self.too_small = too_small;
            self.dirty = false;
        }
    }
}

/// What a reduced action parked for the terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TerminalWork {
    /// Ctrl-L.
    Repaint,
    /// Ctrl-Z, or a stop from outside.
    Suspend,
    /// The run was continued.
    Reenter,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::key_action;
    use ratatui::crossterm::event::KeyCode;

    /// A [`Surface`] that renders each frame to glyphs and keeps them, so a
    /// test can prove what `App::graceful_quit` drew without a real
    /// terminal. Only this module needs it — `Tui` is the one
    /// production `Surface`, and only the quit path's own tests substitute
    /// something else for it.
    #[derive(Default)]
    struct RecordingSurface {
        frames: Vec<String>,
        titles: Vec<Option<String>>,
        bells: usize,
        repaints: usize,
        suspends: usize,
        suspend_refused: Option<crate::tui::NoStop>,
        reentries: usize,
    }

    impl Surface for RecordingSurface {
        fn draw(&mut self, render: impl FnOnce(&mut ratatui::Frame)) -> Drawn {
            self.frames
                .push(crate::golden::render_to_lines(80, 24, render));
            Drawn::Shown
        }

        fn repaint(&mut self) {
            self.repaints += 1;
        }

        fn set_title(&mut self, title: Option<&str>) {
            self.titles.push(title.map(str::to_owned));
        }

        fn ring_bell(&mut self) {
            self.bells += 1;
        }

        fn copy_to_clipboard(&mut self, _text: &str) {}

        fn suspend(&mut self) -> Result<(), crate::tui::NoStop> {
            self.suspends += 1;
            self.suspend_refused.map_or(Ok(()), Err)
        }

        fn reenter(&mut self) {
            self.reentries += 1;
        }
    }

    /// The title is the operator's until they give it up, follows the rates
    /// only when they change, and goes back when the setting is turned off.
    #[test]
    fn the_terminal_title_follows_the_setting_and_writes_only_a_change() {
        let mut app = App::new(Theme::default_dark());
        let mut surface = RecordingSurface::default();
        let now = Instant::now();

        app.draw(&mut surface, now);
        assert!(surface.titles.is_empty(), "off leaves the title alone");

        app.state.preferences.terminal_title = true;
        app.state.rates.down_total_bps = 8.0 * 1024.0 * 1024.0;
        app.draw(&mut surface, now);
        app.draw(&mut surface, now);
        assert_eq!(
            surface.titles,
            [Some("rmule ▼ 8.0 MB/s ▲ 0.0 KB/s".to_string())],
            "written once"
        );

        app.state.preferences.terminal_title = false;
        app.draw(&mut surface, now);
        assert_eq!(surface.titles.last(), Some(&None), "given back");
    }

    #[test]
    fn all_three_themes_render_the_same_glyph_structure() {
        // Spec §7 acceptance: themes differ in style only — the glyph
        // layer must match the blessed dark golden exactly.
        let golden = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/goldens/app_full_frame.txt");
        let dark = std::fs::read_to_string(golden).expect("dark golden blessed");
        for theme in [Theme::light(), Theme::fallback_256()] {
            let mut app = App::new(theme);
            let now = Instant::now();
            let lines = crate::golden::render_to_lines(80, 24, |frame| {
                let content = chrome::draw_frame(frame, &app.state, &app.chrome, &app.theme, now);
                app.views.draw(
                    app.chrome.active,
                    frame,
                    content,
                    &app.state,
                    &app.theme,
                    now,
                );
                chrome::draw_overlays(frame, &app.state, &app.chrome, &app.theme);
            });
            assert_eq!(lines, dark, "theme changed glyphs, not just styles");
        }
    }

    #[test]
    fn golden_full_frame_composition_chrome_plus_view() {
        // The exact z-order App::draw uses: chrome → active view → overlays.
        let mut app = App::new(Theme::default_dark());
        let now = Instant::now();
        crate::golden::assert_golden("app_full_frame", 80, 24, |frame| {
            let content = chrome::draw_frame(frame, &app.state, &app.chrome, &app.theme, now);
            app.views.draw(
                app.chrome.active,
                frame,
                content,
                &app.state,
                &app.theme,
                now,
            );
            chrome::draw_overlays(frame, &app.state, &app.chrome, &app.theme);
        });
    }

    /// The sixth view in its real frame: the digit reaches it, the
    /// compact tab bar the six tabs forced at 80 columns is on the border
    /// above it, and the pane scrolls under the 22 rows chrome leaves.
    #[test]
    fn golden_settings_frame_composition() {
        let mut app = App::new(Theme::default_dark());
        // A named data directory, so the frame draws no platform's own
        // "set RMULE_DATA or HOME / LOCALAPPDATA" words.
        app.state.preferences.data_dir = Some(crate::args::DataDir {
            path: std::path::PathBuf::from("/srv/rmule"),
            source: crate::args::DataDirSource::Flag,
        });
        let now = Instant::now();
        app.reduce(key_action(KeyCode::Char('6')), now);
        crate::golden::assert_golden("app_settings_frame", 80, 24, |frame| {
            let content = chrome::draw_frame(frame, &app.state, &app.chrome, &app.theme, now);
            app.views.draw(
                app.chrome.active,
                frame,
                content,
                &app.state,
                &app.theme,
                now,
            );
            chrome::draw_overlays(frame, &app.state, &app.chrome, &app.theme);
        });
    }

    /// The fifth view in its real frame: the dispatch arm, the content
    /// rect chrome hands it, and the graphs at the actual 78×22 the 80×24
    /// terminal leaves — the standalone view golden is drawn at 78×21.
    #[test]
    fn golden_statistics_frame_composition() {
        let mut app = App::new(Theme::default_dark());
        let base = Instant::now();
        crate::fixture::rate_ticks(
            &mut app.state,
            base,
            90,
            &rmule_core::diagnostics::DiagnosticsSnapshot::default(),
        );
        app.reduce(key_action(KeyCode::Char('5')), base);
        let now = base + std::time::Duration::from_secs(90);
        crate::golden::assert_golden("app_statistics_frame", 80, 24, |frame| {
            let content = chrome::draw_frame(frame, &app.state, &app.chrome, &app.theme, now);
            app.views.draw(
                app.chrome.active,
                frame,
                content,
                &app.state,
                &app.theme,
                now,
            );
            chrome::draw_overlays(frame, &app.state, &app.chrome, &app.theme);
        });
    }

    /// A quit step's frame — the full composition (chrome,
    /// active view, overlays), exactly the z-order `App::draw` uses, with the
    /// status bar naming the step the core announced.
    #[test]
    fn golden_shutdown_frame_composition() {
        let mut app = App::new(Theme::default_dark());
        let now = Instant::now();
        app.reduce(
            Action::Core(rmule_core::CoreEvent::Quitting {
                step: rmule_core::QuitStep::Kad,
            }),
            now,
        );
        crate::golden::assert_golden("app_shutdown_frame", 80, 24, |frame| {
            let content = chrome::draw_frame(frame, &app.state, &app.chrome, &app.theme, now);
            app.views.draw(
                app.chrome.active,
                frame,
                content,
                &app.state,
                &app.theme,
                now,
            );
            chrome::draw_overlays(frame, &app.state, &app.chrome, &app.theme);
        });
    }

    /// The graceful quit's regression proof: before this fix, `Flow::Quit` dropped
    /// the bridge (and the `Core` inside it) with no `Core::quit` call
    /// at all, so the credit checkpoint never flushed. This runs the real
    /// quit path — `graceful_quit`, exactly what `Flow::Quit` now awaits —
    /// over a real `Core` and proves the unconditional checkpoint lands
    /// (`clients.met`, ADR-0041 amended by ADR-0083).
    #[tokio::test(flavor = "multi_thread")]
    async fn quit_runs_the_graceful_shutdown_door_and_flushes_the_credit_checkpoint() {
        let dir = tempfile::tempdir().expect("tempdir");
        let core = rmule_core::Core::builder(
            rmule_core::CoreConfig::default(),
            rmule_testkit::memory_store(),
        )
        .settings(rmule_core::CoreSettings::default())
        .persist_credit_in(dir.path().to_path_buf())
        .build();
        let (actions_tx, mut actions_rx) = mpsc::channel(64);
        let handle = crate::bridge::spawn(core, actions_tx, crate::bridge::BridgeConfig::default());

        let mut app = App::new(Theme::default_dark()).with_client(handle);
        let mut surface = RecordingSurface::default();
        app.graceful_quit(&mut surface, &mut actions_rx).await;

        assert!(
            dir.path().join("clients.met").exists(),
            "Core::quit's unconditional checkpoint must have written clients.met"
        );
    }

    /// A terminal that takes no frame, stalled or gone.
    struct HeldSurface;

    impl Surface for HeldSurface {
        fn draw(&mut self, _render: impl FnOnce(&mut ratatui::Frame)) -> Drawn {
            Drawn::Held
        }

        fn repaint(&mut self) {}

        fn copy_to_clipboard(&mut self, _text: &str) {}

        fn suspend(&mut self) -> Result<(), crate::tui::NoStop> {
            Ok(())
        }

        fn set_title(&mut self, _title: Option<&str>) {}

        fn ring_bell(&mut self) {}

        fn reenter(&mut self) {}
    }

    /// A held frame stays owed, title with it: the title goes out behind the
    /// frame the terminal takes next, never ahead of it.
    #[test]
    fn a_held_frame_leaves_the_state_dirty_and_its_title_owed() {
        let mut app = App::new(Theme::default_dark());
        app.dirty = true;
        app.state.preferences.terminal_title = true;
        let now = Instant::now();

        app.draw(&mut HeldSurface, now);
        assert!(app.dirty);

        let mut surface = RecordingSurface::default();
        app.draw(&mut surface, now);
        assert!(!app.dirty);
        assert_eq!(surface.titles.len(), 1, "the title was still owed");
    }

    /// A key or a signal parks the terminal's work, and the loop does it.
    #[tokio::test(flavor = "multi_thread")]
    async fn ctrl_z_and_ctrl_l_and_a_continue_reach_the_surface() {
        use ratatui::crossterm::event::{Event, KeyEvent, KeyModifiers};

        let ctrl = |code| Event::Key(KeyEvent::new(code, KeyModifiers::CONTROL));
        let (actions_tx, actions_rx) = mpsc::channel(64);
        for action in [
            Action::Input(ctrl(KeyCode::Char('l'))),
            Action::Input(ctrl(KeyCode::Char('z'))),
            Action::Continued,
            Action::Quit,
        ] {
            actions_tx.send(action).await.expect("the bus is open");
        }
        let mut surface = RecordingSurface {
            suspend_refused: Some(crate::tui::NoStop::NoShell),
            ..RecordingSurface::default()
        };
        let app = App::new(Theme::default_dark());

        app.run(&mut surface, actions_rx).await;

        assert_eq!(
            (surface.repaints, surface.suspends, surface.reentries),
            (1, 1, 1)
        );
    }

    /// The flush of a run whose terminal went away is exactly the one a hangup
    /// must not lose: a stop from outside ends the loop through the quit, with
    /// a queued action and a surface that never takes a frame.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_stop_ends_the_run_through_the_quit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let core = rmule_core::Core::builder(
            rmule_core::CoreConfig::default(),
            rmule_testkit::memory_store(),
        )
        .settings(rmule_core::CoreSettings::default())
        .persist_credit_in(dir.path().to_path_buf())
        .build();
        let (actions_tx, actions_rx) = mpsc::channel(64);
        let handle = crate::bridge::spawn(
            core,
            actions_tx.clone(),
            crate::bridge::BridgeConfig::default(),
        );
        actions_tx
            .send(Action::Note(
                crate::words::severity::Severity::Failure,
                crate::words::app::INTERNAL_FAULT,
            ))
            .await
            .expect("the bus is open");
        let stop = Stop::default();
        stop.request();
        let app = App::new(Theme::default_dark())
            .with_stop(stop)
            .with_client(handle);

        app.run(&mut HeldSurface, actions_rx).await;

        assert!(dir.path().join("clients.met").exists());
    }

    /// A core whose quit never ends, so the bridge's grace elapses and it
    /// queues the grace-elapsed notice just before it answers the door.
    struct HangingCore(
        mpsc::Sender<rmule_core::CoreEvent>,
        mpsc::Receiver<rmule_core::CoreEvent>,
    );

    /// Takes every command and does nothing with it.
    struct OpenDoor;

    impl crate::bridge::CommandDoor for OpenDoor {
        async fn send(&self, _: rmule_core::CoreCommand) -> Result<(), rmule_core::CoreError> {
            Ok(())
        }
    }

    impl crate::bridge::CoreHandle for HangingCore {
        type Door = OpenDoor;
        type QuitEvents = mpsc::Receiver<rmule_core::CoreEvent>;

        fn door(&self) -> OpenDoor {
            OpenDoor
        }
        async fn next_event(&mut self) -> Option<rmule_core::CoreEvent> {
            std::future::pending().await
        }
        fn diagnostics_snapshot(&self) -> rmule_core::diagnostics::DiagnosticsSnapshot {
            Default::default()
        }
        fn quit(self) -> mpsc::Receiver<rmule_core::CoreEvent> {
            // The sender leaks with the task, so the stream never ends.
            std::mem::forget(self.0);
            self.1
        }
    }

    /// The grace-elapsed notice is queued on the bus just before the door
    /// answers, so the quit arm must not win the race and leave it
    /// undrawn: the last frame before the terminal is restored names it.
    #[tokio::test(start_paused = true)]
    async fn a_grace_elapsed_quit_draws_its_notice_before_returning() {
        let (tx, rx) = mpsc::channel(1);
        let (actions_tx, mut actions_rx) = mpsc::channel(64);
        let handle = crate::bridge::spawn(
            HangingCore(tx, rx),
            actions_tx,
            crate::bridge::BridgeConfig::default(),
        );
        let mut app = App::new(Theme::default_dark()).with_client(handle);
        let mut surface = RecordingSurface::default();
        app.graceful_quit(&mut surface, &mut actions_rx).await;

        let last = surface.frames.last().expect("quit drew");
        assert!(
            last.contains("Quit ran out of time") && last.contains("may be lost"),
            "the last frame must show the grace-elapsed notice, got:\n{last}"
        );
    }

    /// With no core to flush, quit returns at once, drawing nothing (there is
    /// no step to name).
    #[tokio::test]
    async fn quit_with_no_client_returns_at_once() {
        let mut app = App::new(Theme::default_dark());
        let mut surface = RecordingSurface::default();
        let (_tx, mut actions_rx) = mpsc::channel(1);
        app.graceful_quit(&mut surface, &mut actions_rx).await;
        assert!(surface.frames.is_empty(), "nothing to announce");
    }
}
