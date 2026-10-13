//! Always-on chrome (spec §3.1): the outer frame whose top border is the tab
//! bar and whose bottom border is the 4-segment status bar, plus the help
//! overlay (`?`) and the transient action flash (~3 s amber ✱).
//!
//! Rendering is pure — `UiState` + `ChromeState` + injected `now` → widgets —
//! so every chrome state goldens under `TestBackend`.
use std::time::{Duration, Instant};

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};

use crate::action::Action;
use crate::state::UiState;
use crate::theme::Theme;
use crate::view::ViewId;
use help::draw_help;
use status_bar::render as status_bar;
use tabs::{BRAND, brand_fits, tabs_line};

mod help;

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
    /// Whether the help overlay is up. It is modal while it is: only
    /// `Esc`/`q`/`?` and its scroll keys act, and mouse input is dropped.
    pub help_open: bool,
    /// The help overlay's first line on screen, and how far it can scroll and
    /// page as the last draw laid it out — the same draw-time cache as
    /// `frame_width`.
    help_scroll: help::HelpScroll,
    /// The build line the help overlay opens with.
    help_version: help::HelpVersion,
    flash: Option<Flash>,
    /// Frame width from the last draw, cached because the tab bar's *form*
    /// depends on it and a click has to be hit-tested against the form that
    /// was actually drawn. The same draw-time cache the table views keep for
    /// their row geometry; `Cell` because drawing is otherwise a `&self` pass.
    frame_width: std::cell::Cell<u16>,
}

/// One frame of chrome furniture (frame + tabs + status bar). Returns the
/// content rect the active view draws into; overlays go on top afterwards
/// via [`draw_overlays`], so the z-order is chrome → view → modal.
///
/// When the status info text cannot fit the bottom border whole (the
/// never-truncate rule), it spills onto wrapped rows just above the border and the
/// returned content rect shrinks by exactly those rows.
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
        .title_bottom(status.border);
    if show_brand {
        outer = outer.title_top(Line::from(Span::styled(BRAND, theme.dim_text())).right_aligned());
    }
    let mut content = outer.inner(area);
    frame.render_widget(outer, area);

    let spill = u16::try_from(status.overflow.len()).unwrap_or(u16::MAX);
    if spill > 0 && content.height > spill {
        let strip = Rect::new(content.x, content.bottom() - spill, content.width, spill);
        frame.render_widget(Paragraph::new(status.overflow), strip);
        content.height -= spill;
    }
    content
}

/// Chrome-owned overlays, drawn after the view so they sit on top.
pub fn draw_overlays(frame: &mut Frame, chrome: &ChromeState, theme: &Theme) {
    if chrome.help_open {
        draw_help(
            frame,
            frame.area(),
            &chrome.help_scroll,
            &chrome.help_version,
            theme,
        );
    }
}

/// Char width of one status segment.
fn spans_width(spans: &[Span<'static>]) -> usize {
    spans.iter().map(|span| span.content.chars().count()).sum()
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
                true
            }
            Action::ScrollHelp(lines) => self.help_scroll.scroll(*lines),
            Action::DismissOverlay => {
                let was_open = self.help_open;
                self.help_open = false;
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
            | Action::Note(_)
            | Action::Input(_)
            | Action::Command(_)
            | Action::Commands(_)
            | Action::Actions(_)
            | Action::CopyLink(_)
            | Action::Preference(_)
            | Action::ConfirmDownloadDir(_)
            | Action::ForgetSearch(_)
            | Action::SearchRelated(_)
            | Action::StartKad
            | Action::Preview(_)
            | Action::Quit => false,
        }
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
