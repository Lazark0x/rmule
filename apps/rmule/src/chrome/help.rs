//! The help overlay: this build's version line, then the spec's global
//! bindings in a two-column list.
//!
//! Drawn over the frame without disturbing it — the tab bar and the status
//! bar stay whole outside it, so dismissing the overlay restores exactly what
//! was there. When the bindings outgrow the frame it scrolls rather than
//! dropping a row to fit:
//! `j`/`k` a line, `PgDn`/`PgUp` a page, `g`/`G` the ends, and its border
//! says which lines show.

use std::cell::Cell;

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph};

use crate::theme::Theme;
use crate::views::centered;
use crate::wrap::labeled_lines;

/// Where the help overlay is scrolled to, and how far it can go, as the last
/// draw laid it out. `Cell`s because drawing is a `&self` pass.
#[derive(Default)]
pub(super) struct HelpScroll {
    /// The first line on screen.
    offset: Cell<u16>,
    /// The furthest the first line can go: lines beyond the room.
    max: Cell<u16>,
    /// Lines on screen at once.
    room: Cell<u16>,
}

impl HelpScroll {
    /// Back to the first line, as the overlay opens.
    pub(super) fn top(&self) {
        self.offset.set(0);
    }

    /// Move by `lines` within what the last draw could show; whether it
    /// moved.
    pub(super) fn scroll(&self, lines: i16) -> bool {
        let before = self.offset.get();
        let after = if lines < 0 {
            before.saturating_sub(lines.unsigned_abs())
        } else {
            before.saturating_add(lines.unsigned_abs())
        }
        .min(self.max.get());
        self.offset.set(after);
        after != before
    }

    /// A page: the lines on screen at once, at least one.
    pub(super) fn page(&self) -> u16 {
        self.room.get().max(1)
    }
}

/// The build line the overlay opens with: the one version line `--version`
/// prints ([`version_line`](crate::words::front_door::version_line)), so the
/// two cannot drift.
pub(super) struct HelpVersion(String);

impl HelpVersion {
    /// The line for `build`.
    pub(super) fn of(build: crate::args::Build) -> Self {
        Self(crate::words::front_door::version_line(build))
    }
}

impl Default for HelpVersion {
    /// This binary's build.
    fn default() -> Self {
        Self::of(crate::args::BUILD)
    }
}

/// Key-column width of the help overlay; descriptions wrap to the right of it.
const KEY_COL_W: usize = 16;

/// The `?` overlay: this build's version line, then every binding, modal over
/// the frame, between the tab bar and the status bar.
pub(super) fn draw_help(
    frame: &mut Frame,
    area: Rect,
    scroll: &HelpScroll,
    version: &HelpVersion,
    theme: &Theme,
) {
    let area = Rect::new(
        area.x,
        area.y.saturating_add(1),
        area.width,
        area.height.saturating_sub(2),
    );
    let rows: &[(&str, &str)] = &[
        ("1–6", "switch view directly"),
        ("h / l", "previous / next view"),
        (
            "[ / ]",
            "Searches: previous / next held search / Shared: filter by directory",
        ),
        ("j/k  ↑/↓", "select row in focused pane"),
        ("g / G", "top / bottom"),
        ("Tab / Shift-Tab", "cycle panes (accent border = focus)"),
        ("m / Enter", "row action menu"),
        ("/", "Searches: focus query input"),
        ("← / →", "Searches: pick method (input focused)"),
        ("o", "Searches: type/size/sources/extension filters"),
        (
            "x / n",
            "Searches: stop or close a search / server's next page",
        ),
        ("s / S", "sort the focused table by next column / reverse"),
        ("a", "Shared: filter / Networks: add server"),
        ("U", "Networks: update server list from URL"),
        ("5 / 6", "Statistics (display-only) / Settings"),
        ("Enter  ← / →", "Settings: edit a field / step a selector"),
        ("x", "Settings: stop sharing the selected directory"),
        (
            "c",
            "Networks: connect to the selected server, or disconnect from the one you are on",
        ),
        ("K", "Networks: start or stop Kad"),
        (
            "p / C",
            "pause/resume selected download / clear all completed",
        ),
        ("L", "Transfers: add a download from a pasted eD2k link"),
        (
            "v",
            "Transfers: preview the selected download in the player set in Settings",
        ),
        ("?", "this help; j/k, PgUp/PgDn scroll it when it is long"),
        ("q / Esc", "quit (top level) / dismiss (modal)"),
        (
            "mouse",
            "click tab/row selects, header sorts, wheel scrolls",
        ),
    ];
    // Greedy width: the overlay takes whatever it needs to show every
    // binding whole, and only wraps the description column when the frame is
    // narrower than that.
    let key_w = KEY_COL_W;
    let natural = rows
        .iter()
        .map(|(_, what)| key_w + 3 + what.chars().count())
        .max()
        .unwrap_or(0)
        .max(version.0.chars().count() + 3);
    let width = u16::try_from(natural)
        .unwrap_or(u16::MAX)
        .clamp(3, area.width.max(3));
    let inner_w = usize::from(width).saturating_sub(2);
    let desc_w = inner_w.saturating_sub(key_w + 1).max(1);

    // The build first, where `?` opens, so a hands-on check tells two builds
    // apart in one keypress; it wraps rather than being cut.
    let mut lines = labeled_lines(
        Span::raw(" "),
        &version.0,
        Style::new().fg(theme.fg),
        inner_w.saturating_sub(1).max(1),
    );
    lines.push(Line::default());
    // Continuation lines hang under the description column, so a wrapped
    // binding still reads as one row.
    lines.extend(rows.iter().flat_map(|(key, what)| {
        labeled_lines(
            Span::styled(format!(" {key:<key_w$}"), Style::new().fg(theme.accent)),
            what,
            Style::new().fg(theme.fg),
            desc_w,
        )
    }));

    let total = u16::try_from(lines.len()).unwrap_or(u16::MAX);
    let height = total.saturating_add(2).min(area.height);
    let room = height.saturating_sub(2);
    scroll.room.set(room);
    scroll.max.set(total.saturating_sub(room));
    let offset = scroll.offset.get().min(scroll.max.get());
    scroll.offset.set(offset);
    let modal = centered(area, width, height);
    frame.render_widget(Clear, modal);
    // The border says which lines show while not all of them do.
    let place = (room < total).then(|| {
        let last = offset.saturating_add(room).min(total);
        format!(" {}–{last} of {total} · j/k ", offset + 1)
    });
    let mut block = Block::bordered()
        .border_style(theme.chrome())
        .style(Style::new().fg(theme.fg).bg(theme.panel))
        .title_top(Line::from(Span::styled(" Help ", theme.tab_active())));
    if let Some(place) = place {
        block =
            block.title_bottom(Line::from(Span::styled(place, theme.dim_text())).right_aligned());
    }
    let inner = block.inner(modal);
    frame.render_widget(block, modal);
    let shown: Vec<Line<'static>> = lines
        .into_iter()
        .skip(usize::from(offset))
        .take(usize::from(room))
        .collect();
    frame.render_widget(Paragraph::new(shown), inner);
}

#[cfg(test)]
mod tests {
    use super::super::{ChromeState, draw_frame, draw_overlays};
    use super::*;
    use crate::action::Action;
    use crate::fixture::*;
    use crate::golden::assert_golden;
    use crate::state::UiState;

    /// A fixed build, so the goldens do not move with every commit.
    fn chrome() -> ChromeState {
        ChromeState {
            help_version: HelpVersion::of(crate::args::Build {
                version: "0.1.0",
                commit: "0123456789ab",
                committed: "2026-09-30",
                dirty: false,
            }),
            ..ChromeState::default()
        }
    }

    /// The overlay is a modal *over* the frame, not a replacement for it: at
    /// the canonical 80×24 it has to fit between the tab bar and the status
    /// bar, or it half-covers both and reads as a rendering fault. Adding a
    /// binding row is exactly what breaks this — one change added three and had to
    /// compress them to two — so the fit is pinned rather than noticed later.
    #[test]
    fn the_help_overlay_leaves_both_pieces_of_chrome_whole() {
        let theme = Theme::default_dark();
        let mut chrome = chrome();
        chrome.update(&Action::ToggleHelp, now());
        let rendered = crate::golden::render_to_lines(80, 24, |frame| {
            draw_frame(frame, &UiState::default(), &chrome, &theme, now());
            draw_overlays(frame, &chrome, &theme);
        });
        let rows: Vec<&str> = rendered.lines().collect();
        assert!(
            rows[0].starts_with("┌ 1 Networks"),
            "tab bar covered: {:?}",
            rows[0]
        );
        assert!(
            rows[23].starts_with("└ —"),
            "status bar covered: {:?}",
            rows[23]
        );
    }

    #[test]
    fn golden_help_overlay_lists_the_spec_bindings() {
        let mut chrome = chrome();
        chrome.update(&Action::ToggleHelp, now());
        assert_golden("chrome_help", 80, 24, |frame| {
            draw_frame(
                frame,
                &UiState::default(),
                &chrome,
                &Theme::default_dark(),
                now(),
            );
            draw_overlays(frame, &chrome, &Theme::default_dark());
        });
    }

    /// An overlay taller than 80×24 scrolls rather than dropping a row. The
    /// `5 / 6` row and the last binding
    /// are both reachable, the border says which lines show, and the chrome
    /// stays whole at every position.
    #[test]
    fn golden_help_overlay_scrolled_to_its_end() {
        let theme = Theme::default_dark();
        let mut chrome = chrome();
        chrome.update(&Action::ToggleHelp, now());
        let draw = |chrome: &ChromeState| {
            crate::golden::render_to_lines(80, 24, |frame| {
                draw_frame(frame, &UiState::default(), chrome, &theme, now());
                draw_overlays(frame, chrome, &theme);
            })
        };
        let top = draw(&chrome);
        assert!(top.contains("5 / 6"), "{top}");
        assert!(!top.contains("mouse"), "{top}");
        assert!(chrome.update(&Action::ScrollHelp(i16::MAX), now()));
        assert_golden("chrome_help_scrolled", 80, 24, |frame| {
            draw_frame(frame, &UiState::default(), &chrome, &theme, now());
            draw_overlays(frame, &chrome, &theme);
        });
        let end = draw(&chrome);
        assert!(end.contains("mouse"), "{end}");
        let rows: Vec<&str> = end.lines().collect();
        assert!(rows[0].starts_with("┌ 1 Networks"), "{}", rows[0]);
        assert!(rows[23].starts_with("└ —"), "{}", rows[23]);
        assert!(
            !chrome.update(&Action::ScrollHelp(1), now()),
            "the end holds"
        );
        assert!(chrome.update(&Action::ScrollHelp(i16::MIN), now()));
        assert_eq!(draw(&chrome), top);
    }

    /// While help is up its keys scroll it; everything else but the ways out
    /// stays inert.
    #[test]
    fn help_keys_scroll_the_overlay() {
        use ratatui::crossterm::event::KeyCode;
        let mut chrome = chrome();
        chrome.update(&Action::ToggleHelp, now());
        let map = |code| crate::input::map_key(&chrome, press(code));
        assert!(matches!(
            map(KeyCode::Char('j')),
            Some(Action::ScrollHelp(1))
        ));
        assert!(matches!(map(KeyCode::Up), Some(Action::ScrollHelp(-1))));
        assert!(matches!(
            map(KeyCode::Char('G')),
            Some(Action::ScrollHelp(i16::MAX))
        ));
        assert!(map(KeyCode::Char('1')).is_none());
    }
}
