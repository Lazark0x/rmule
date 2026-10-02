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
use crate::theme::Theme;
use crate::tui::{Surface, Tui};
use views::Views;

mod history;
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
    /// The config store the Settings tab writes through. `None` = a
    /// UI-only run: an edit degrades to the honest flash, exactly as a core
    /// command does without a client.
    config: Option<crate::config::SharedConfig>,
    dirty: bool,
    /// A link waiting for the OSC 52 write (needs the terminal, which
    /// `reduce` never sees); flushed by the run loop.
    pending_copy: Option<String>,
    /// The command door to the core. `None` = UI-only run: commands
    /// degrade to an honest flash.
    client: Option<BridgeHandle>,
    /// Commands awaiting the async send (reduce is sync); flushed by the
    /// run loop in order.
    pending_commands: Vec<rmule_core::CoreCommand>,
    /// The Kad join's start lane: sent on the run's first eD2k
    /// login, and on the operator's `K`. `None` on a UI-only run, where there
    /// is no join to start.
    kad_start: Option<crate::kad::KadStarter>,
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
    /// The Run Log's level, shared with its writers: the Settings row turns
    /// it, and the next line written follows.
    run_log: crate::run_log::LevelHandle,
    /// The File History's ask, kept to one out at a time.
    history: history::HistoryPoll,
}

/// What one action did to the loop.
enum Flow {
    Continue,
    Quit,
}

impl App {
    /// A UI-only app: no core, no config store, no Kad arm. Every `with_*`
    /// below upgrades one of those, so a startup that fails partway still
    /// yields a running UI that flashes honestly instead of pretending.
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
            pending_copy: None,
            client: None,
            pending_commands: Vec::new(),
            kad_start: None,
            kad_first_login_owed: false,
            kad_join_ended_told: false,
            last_server_unsaved_told: false,
            run_log: crate::run_log::LevelHandle::default(),
            history: history::HistoryPoll::default(),
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
        self.state.session = Some(session);
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
        self.run_log
            .set(crate::run_log::Level::from_full(preferences.run_log_full));
        self.views.searches.restore_sort(&preferences.table_sorts);
        self.views.transfers.restore_sort(&preferences.table_sorts);
        self.views.networks.restore_sort(&preferences.table_sorts);
        self.views.shared.restore_sort(&preferences.table_sorts);
        self.state.preferences = preferences;
        self.config = Some(config);
        self
    }

    /// Share the Run Log's level handle, so the Settings row turns the level
    /// its writers read.
    #[must_use]
    pub fn with_run_log(mut self, level: crate::run_log::LevelHandle) -> Self {
        self.run_log = level;
        self
    }

    /// Install the Kad join's start lane: the join parked on its
    /// other half starts a node when this app observes its first eD2k login,
    /// or when the operator presses `K`, and never at startup. Without one
    /// the app never starts a join — a UI-only run has no core to join with,
    /// and the Networks panel says "Kad: off" for the honest reason.
    #[must_use]
    pub fn with_kad_start(mut self, start: crate::kad::KadStarter) -> Self {
        self.kad_start = Some(start);
        self.kad_first_login_owed = true;
        self
    }

    /// Drive the UI until quit or until every action producer is gone.
    pub async fn run(
        mut self,
        tui: &mut Tui,
        mut actions: mpsc::Receiver<Action>,
    ) -> std::io::Result<()> {
        let mut render = tokio::time::interval(RENDER_INTERVAL);
        render.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                maybe = actions.recv() => {
                    let Some(action) = maybe else { break };
                    let now = Instant::now();
                    let immediate = matches!(action, Action::Input(_));
                    match self.reduce(action, now) {
                        Flow::Quit => {
                            self.graceful_quit(tui, &mut actions).await?;
                            break;
                        }
                        Flow::Continue => {}
                    }
                    if let Some(link) = self.pending_copy.take() {
                        tui.copy_to_clipboard(&link)?;
                    }
                    self.flush_commands(now).await;
                    // ADR-0069: input redraws immediately; core bursts wait
                    // for the render tick and collapse into one frame.
                    if immediate && self.dirty {
                        self.draw(tui, now)?;
                    }
                }
                _ = render.tick() => {
                    let now = Instant::now();
                    // A flash expiring is a repaint the state never asked for.
                    if self.chrome.expire_flash(now) {
                        self.dirty = true;
                    }
                    if self.dirty {
                        self.draw(tui, now)?;
                    }
                }
            }
        }
        Ok(())
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
    /// is restored only once this returns and the loop breaks. A UI-only run
    /// (`self.client` is `None`) has no core to quit and returns at once,
    /// drawing nothing.
    ///
    /// `actions` is the same bus `App::run` reads — the only door onto
    /// core's events this app has, since the bridge is single-consumer; it
    /// is drained here while quit runs so the bridge's forwarding never
    /// stalls on a full bus.
    async fn graceful_quit<S: Surface>(
        &mut self,
        tui: &mut S,
        actions: &mut mpsc::Receiver<Action>,
    ) -> std::io::Result<()> {
        let Some(client) = self.client.clone() else {
            return Ok(());
        };
        let now = Instant::now();
        self.chrome
            .update(&Action::Flash(crate::words::app::SHUTTING_DOWN), now);
        self.dirty = true;
        self.draw(tui, now)?;

        let quit = client.graceful_shutdown();
        tokio::pin!(quit);
        loop {
            tokio::select! {
                biased;
                _ = &mut quit => return Ok(()),
                action = actions.recv() => match action {
                    Some(
                        step @ (Action::Core(rmule_core::CoreEvent::Quitting { .. })
                        | Action::Flash(_)),
                    ) => {
                        // Quitting steps are the core's own progress; a Flash
                        // here is the bridge's grace-elapsed notice — both
                        // are the status bar's
                        // receipt for a wait that is not actually stuck, so
                        // both get drawn instead of falling into `Some(_)`.
                        let now = Instant::now();
                        let _ = self.reduce(step, now);
                        self.draw(tui, now)?;
                    }
                    Some(_) => {}
                    None => {
                        quit.await;
                        return Ok(());
                    }
                },
            }
        }
    }

    /// Forward queued commands through the client, in order. A send failing
    /// means the core stopped — `Action::CoreClosed` follows on the bus and
    /// renders the honest state, so failures are not re-flashed here.
    async fn flush_commands(&mut self, _now: Instant) {
        if self.pending_commands.is_empty() {
            return;
        }
        let Some(client) = self.client.clone() else {
            self.pending_commands.clear();
            return;
        };
        for command in self.pending_commands.drain(..) {
            if client.send(command).await.is_err() {
                break;
            }
        }
    }

    fn draw<S: Surface>(&mut self, tui: &mut S, now: Instant) -> std::io::Result<()> {
        let state = &self.state;
        let chrome_state = &self.chrome;
        let theme = &self.theme;
        let views = &mut self.views;
        tui.draw(|frame| {
            let content = chrome::draw_frame(frame, state, chrome_state, theme, now);
            views.draw(chrome_state.active, frame, content, state, theme, now);
            chrome::draw_overlays(frame, chrome_state, theme);
        })?;
        self.dirty = false;
        Ok(())
    }
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
    }

    impl Surface for RecordingSurface {
        fn draw(&mut self, render: impl FnOnce(&mut ratatui::Frame)) -> std::io::Result<()> {
            self.frames
                .push(crate::golden::render_to_lines(80, 24, render));
            Ok(())
        }
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
                chrome::draw_overlays(frame, &app.chrome, &app.theme);
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
            chrome::draw_overlays(frame, &app.chrome, &app.theme);
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
            chrome::draw_overlays(frame, &app.chrome, &app.theme);
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
            chrome::draw_overlays(frame, &app.chrome, &app.theme);
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
            chrome::draw_overlays(frame, &app.chrome, &app.theme);
        });
    }

    /// The graceful quit's regression proof: before this fix, `Flow::Quit` dropped
    /// the bridge (and the `Core` inside it) with no `Core::shutdown()` call
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
        .persist_credit_in(dir.path().to_path_buf())
        .build();
        let (actions_tx, mut actions_rx) = mpsc::channel(64);
        let handle = crate::bridge::spawn(core, actions_tx, crate::bridge::BridgeConfig::default());

        let mut app = App::new(Theme::default_dark()).with_client(handle);
        let mut surface = RecordingSurface::default();
        app.graceful_quit(&mut surface, &mut actions_rx)
            .await
            .expect("draw succeeds");

        assert!(
            dir.path().join("clients.met").exists(),
            "Core::shutdown()'s unconditional checkpoint must have written clients.met"
        );
    }

    /// A UI-only run (no core ever attached) has nothing to flush — quit
    /// must return at once rather than reach for an absent client, drawing
    /// nothing (there is no step to name).
    #[tokio::test]
    async fn quit_on_a_ui_only_run_returns_with_no_client() {
        let mut app = App::new(Theme::default_dark());
        let mut surface = RecordingSurface::default();
        let (_tx, mut actions_rx) = mpsc::channel(1);
        app.graceful_quit(&mut surface, &mut actions_rx)
            .await
            .expect("draw succeeds");
        assert!(
            surface.frames.is_empty(),
            "a UI-only run has nothing to announce"
        );
    }
}
