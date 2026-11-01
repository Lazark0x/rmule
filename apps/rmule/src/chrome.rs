//! Always-on chrome (spec §3.1): the outer frame whose top border is the tab
//! bar and whose bottom border is the 4-segment status bar, plus the help
//! overlay (`?`) and the transient action flash (~3 s ✱).
//!
//! Rendering is pure — `UiState` + `ChromeState` + injected `now` → widgets —
//! so every chrome state goldens under `TestBackend`.
use crate::wrap::display_width;
use std::time::{Duration, Instant};

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Block;

use crate::action::Action;
use crate::rates::format_rate;
use crate::state::UiState;
use crate::theme::Theme;
use crate::view::ViewId;
use help::draw_help;
use status_bar::render as status_bar;
use tabs::{BRAND, brand_fits, tabs_line};

mod help;

mod quit_confirm;
mod status_bar;
mod tabs;

pub use tabs::tab_at;

/// How long an action flash stays up (spec §3.1: ~3 s).
pub const FLASH_DURATION: Duration = Duration::from_secs(3);

struct Flash {
    text: crate::words::Sentence,
    at: Instant,
}

/// Chrome view state (ADR-0069: components hold view state only).
#[derive(Default)]
pub struct ChromeState {
    /// The view whose content fills the frame.
    pub active: ViewId,
    /// Whether the help overlay is up. It is modal while it is: `Esc`, `?` and
    /// its scroll keys act, every other key types into its filter, and only
    /// the wheel of the mouse acts.
    pub help_open: bool,
    /// Whether the quit confirm is up, the same kind of modal as help.
    pub quit_open: bool,
    /// The help overlay's first line on screen, and how far it can scroll and
    /// page as the last draw laid it out — the same draw-time cache as
    /// `frame_width`.
    help_scroll: help::HelpScroll,
    /// The build line the help overlay opens with.
    help_version: help::HelpVersion,
    /// What is typed over the help overlay, which narrows it.
    help_filter: crate::row_filter::RowFilter,
    /// Whether a view's text field holds the keyboard, as the app read it
    /// before this frame: the status bar then names the way out of it.
    pub text_open: std::cell::Cell<bool>,
    flash: Option<Flash>,
    /// Frame width from the last draw, cached because the tab bar's *form*
    /// depends on it and a click has to be hit-tested against the form that
    /// was actually drawn. The same draw-time cache the table views keep for
    /// their row geometry; `Cell` because drawing is otherwise a `&self` pass.
    frame_width: std::cell::Cell<u16>,
}

/// One frame of chrome furniture (frame + tabs + status bar). Returns the
/// content rect the active view draws into; overlays go on top afterwards
/// via [`draw_overlays`], so the z-order is chrome → view → modal. The rect
/// is the frame's inside at any status text: the bar takes no rows.
pub fn draw_frame(
    frame: &mut Frame,
    state: &UiState,
    chrome: &ChromeState,
    theme: &Theme,
    now: Instant,
) -> Rect {
    let area = frame.area();
    frame.render_widget(Block::new().style(theme.base()), area);
    chrome.frame_width.set(area.width);

    let status = status_bar(state, chrome, theme, now, area.width);
    let tabs = tabs_line(chrome.active, area.width, theme);
    let show_brand = brand_fits(tabs.width(), area.width);
    let mut outer = Block::bordered()
        .border_style(theme.chrome())
        .title_top(tabs)
        .title_bottom(status.left)
        .title_bottom(status.right.right_aligned());
    if show_brand {
        outer = outer.title_top(Line::from(Span::styled(BRAND, theme.dim_text())).right_aligned());
    }
    let content = outer.inner(area);
    frame.render_widget(outer, area);
    content
}

/// Chrome-owned overlays, drawn after the view so they sit on top. Where the
/// caret of the overlay's text field is.
pub fn draw_overlays(
    frame: &mut Frame,
    state: &UiState,
    chrome: &ChromeState,
    theme: &Theme,
) -> Option<ratatui::layout::Position> {
    if chrome.quit_open {
        quit_confirm::draw(frame, state.quit_cost(), theme);
        None
    } else if chrome.help_open {
        draw_help(
            frame,
            frame.area(),
            (&chrome.help_scroll, &chrome.help_filter),
            (&chrome.help_version, chrome.active),
            theme,
        )
    } else {
        None
    }
}

/// The terminal's title this state asks for; `None` while the setting is off.
#[must_use]
pub fn terminal_title(state: &UiState) -> Option<String> {
    state.preferences.terminal_title.then(|| {
        crate::words::app::terminal_title(
            &format_rate(state.rates.down_total_bps),
            &format_rate(state.rates.up_total_bps),
            state.tally(),
        )
    })
}

/// Char width of one status segment.
fn spans_width(spans: &[Span<'static>]) -> usize {
    spans.iter().map(|span| display_width(&span.content)).sum()
}

impl ChromeState {
    /// Fold a chrome-routed action; other arms are not chrome's and return
    /// `false`. The render dirty hint mirrors `UiState::apply`.
    pub fn update(&mut self, action: &Action, now: Instant) -> bool {
        match action {
            Action::SwitchView(view) => {
                let changed = self.active != *view;
                self.active = *view;
                changed
            }
            Action::CycleView(step) => {
                self.active = if *step >= 0 {
                    self.active.next()
                } else {
                    self.active.prev()
                };
                true
            }
            Action::ToggleHelp => {
                self.help_open = !self.help_open;
                self.help_scroll.top();
                self.help_filter = crate::row_filter::RowFilter::typing_from_the_start();
                true
            }
            Action::HelpKey(key) => {
                self.help_filter.key(key, true);
                // Enter takes nothing from a list: the field stays.
                self.help_filter.keep_typing();
                self.help_scroll.top();
                true
            }
            Action::ScrollHelp(lines) => self.help_scroll.scroll(*lines),
            Action::AskQuit => {
                self.quit_open = true;
                true
            }
            Action::DismissOverlay => {
                let was_open = self.help_open || self.quit_open;
                self.help_open = false;
                self.quit_open = false;
                was_open
            }
            Action::Flash(text) => {
                self.flash = Some(Flash {
                    text: text.clone(),
                    at: now,
                });
                true
            }
            Action::Core(_)
            | Action::Snapshot(_)
            | Action::CoreClosed
            | Action::Note(..)
            | Action::Input(_)
            | Action::Command(_)
            | Action::Commands(_)
            | Action::Actions(_)
            | Action::CopyLink(_)
            | Action::Preference(_)
            | Action::SettingsEdit(_)
            | Action::ConfirmDownloadDir(_)
            | Action::ForgetSearch(_)
            | Action::RestoreSearch(_)
            | Action::SearchRelated(_)
            | Action::StartKad
            | Action::Preview(_)
            | Action::Quit
            | Action::Repaint
            | Action::Suspend
            | Action::Continued => false,
        }
    }

    /// Whether anything is typed over the help overlay.
    #[must_use]
    pub(crate) fn help_typed(&self) -> bool {
        !self.help_filter.is_empty()
    }

    /// How many lines a page of the help overlay is, as last drawn.
    #[must_use]
    pub fn help_page(&self) -> u16 {
        self.help_scroll.page()
    }

    /// Live flash text, if any (pure read; expiry is time-based).
    #[must_use]
    pub fn flash_text(&self, now: Instant) -> Option<&str> {
        self.flash
            .as_ref()
            .filter(|flash| now.saturating_duration_since(flash.at) < FLASH_DURATION)
            .map(|flash| flash.text.as_str())
    }

    /// Drop an expired flash; returns true exactly once per flash so the
    /// render tick repaints the status bar back to the info feed.
    pub fn expire_flash(&mut self, now: Instant) -> bool {
        if self.flash.is_some() && self.flash_text(now).is_none() {
            self.flash = None;
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::*;
    use crate::golden::assert_golden;

    #[test]
    fn switching_and_cycling_track_the_active_view() {
        let mut chrome = ChromeState::default();
        assert_eq!(chrome.active, ViewId::Networks);
        assert!(chrome.update(&Action::SwitchView(ViewId::Transfers), now()));
        assert_eq!(chrome.active, ViewId::Transfers);
        assert!(
            !chrome.update(&Action::SwitchView(ViewId::Transfers), now()),
            "no-op switch is not dirty"
        );
        chrome.update(&Action::CycleView(1), now());
        assert_eq!(chrome.active, ViewId::SharedFiles);
        chrome.update(&Action::CycleView(-1), now());
        assert_eq!(chrome.active, ViewId::Transfers);
    }

    #[test]
    fn flash_shows_then_expires_exactly_once() {
        let mut chrome = ChromeState::default();
        let t0 = now();
        chrome.update(
            &Action::Flash(crate::words::Sentence::for_test("paused")),
            t0,
        );
        assert_eq!(
            chrome.flash_text(t0 + Duration::from_secs(2)),
            Some("paused")
        );
        assert_eq!(chrome.flash_text(t0 + FLASH_DURATION), None);
        assert!(
            !chrome.expire_flash(t0 + Duration::from_secs(2)),
            "live flash stays"
        );
        assert!(
            chrome.expire_flash(t0 + FLASH_DURATION),
            "expiry repaints once"
        );
        assert!(!chrome.expire_flash(t0 + FLASH_DURATION), "…and only once");
    }

    #[test]
    fn golden_chrome_flash_beats_the_notable_text() {
        let t0 = now();
        let mut chrome = ChromeState::default();
        chrome.update(
            &Action::Flash(crate::words::Sentence::for_test("download paused")),
            t0,
        );
        assert_golden("chrome_flash", 80, 24, |frame| {
            draw_frame(
                frame,
                &connected_state(),
                &chrome,
                &Theme::default_dark(),
                t0,
            );
        });
    }
}
