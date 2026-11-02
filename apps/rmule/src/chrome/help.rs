//! The help overlay: this build's version line, then the tab the operator
//! came from, what every tab shares, the other tabs and the words the screens
//! use, each a table under its title. What is typed narrows them, on the one
//! Row Filter, so help is also how a key is found.
//!
//! Drawn over the frame without disturbing it — the tab bar and the status
//! bar stay whole outside it, so dismissing the overlay restores exactly what
//! was there. When the bindings outgrow the frame it scrolls rather than
//! dropping a row to fit: `↑`/`↓` a line, `PgDn`/`PgUp` a page, `Home`/`End`
//! the ends, and its Viewport draws its bar and says which lines show.

use std::cell::Cell;

use ratatui::Frame;
use ratatui::layout::{Position, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph};

use crate::row_filter::RowFilter;
use crate::row_selection::viewport::{self, Viewport};
use crate::table_sort::RowMove;
use crate::theme::Theme;
use crate::view::ViewId;
use crate::views::centered;
use crate::words::help::{Binding, Section, sections};
use crate::words::labels;
use crate::wrap::{clamp_u16, display_width, labeled_lines};

/// Where the help overlay is scrolled to, as the last draw laid it out: its
/// Viewport, in a `Cell` because drawing is a `&self` pass.
#[derive(Default)]
pub(super) struct HelpScroll(Cell<Viewport>);

impl HelpScroll {
    /// Back to the first line, as the overlay opens.
    pub(super) fn top(&self) {
        self.0.set(Viewport::default());
    }

    /// Move by `lines` within what the last draw could show; whether it
    /// moved.
    pub(super) fn scroll(&self, lines: i16) -> bool {
        let mut viewport = self.0.get();
        let moved = viewport.scroll(RowMove::Step(isize::from(lines)));
        self.0.set(viewport);
        moved
    }

    /// A page: the lines on screen at once, at least one.
    pub(super) fn page(&self) -> u16 {
        u16::try_from(self.0.get().page()).unwrap_or(u16::MAX)
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

/// A table's rows that hold what is typed; its title holding it keeps them all.
fn kept(section: &Section, filter: &RowFilter) -> Vec<Binding> {
    let whole = filter.keeps([section.title]);
    section
        .rows
        .iter()
        .copied()
        .filter(|(key, what)| whole || filter.keeps([*key, *what]))
        .collect()
}

/// The `?` overlay: this build's version line, then the tables `active` asks
/// for, narrowed to what is typed, modal over the frame, between the tab bar
/// and the status bar. Where the caret is.
pub(super) fn draw_help(
    frame: &mut Frame,
    area: Rect,
    (scroll, filter): (&HelpScroll, &RowFilter),
    (version, active): (&HelpVersion, ViewId),
    theme: &Theme,
) -> Option<Position> {
    let area = Rect::new(
        area.x,
        area.y.saturating_add(1),
        area.width,
        area.height.saturating_sub(2),
    );
    let sections = sections(active, theme.colourless());
    let tables: Vec<(&str, Vec<Binding>)> = sections
        .iter()
        .map(|section| (section.title, kept(section, filter)))
        .filter(|(_, rows)| !rows.is_empty())
        .collect();
    let kept_rows = tables.iter().map(|(_, rows)| rows.len()).sum();
    let total_rows = sections.iter().map(|section| section.rows.len()).sum();
    // Greedy width: the overlay takes whatever it needs to show every
    // binding whole, and only wraps the description column when the frame is
    // narrower than that. Its width does not follow the filter: the panel
    // stands still as the operator types.
    let key_w = sections
        .iter()
        .flat_map(|section| section.rows.iter())
        .map(|(key, _)| display_width(key))
        .max()
        .unwrap_or(0)
        + 1;
    let natural = sections
        .iter()
        .flat_map(|section| section.rows.iter())
        .map(|(_, what)| key_w + 3 + display_width(what))
        .max()
        .unwrap_or(0)
        .max(display_width(&version.0) + 3);
    let width = u16::try_from(natural)
        .unwrap_or(u16::MAX)
        .clamp(3, area.width.max(3));

    let lines_at = |inner_w: usize| {
        let desc_w = inner_w.saturating_sub(key_w + 1).max(1);
        // The build first, where `?` opens, so a hands-on check tells two
        // builds apart in one keypress; it wraps rather than being cut.
        let mut lines = labeled_lines(
            Span::raw(" "),
            &version.0,
            Style::new().fg(theme.fg),
            inner_w.saturating_sub(1).max(1),
        );
        for (title, rows) in &tables {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                format!(" {title}"),
                Style::new().fg(theme.highlight),
            )));
            // Continuation lines hang under the description column, so a
            // wrapped binding still reads as one row.
            lines.extend(rows.iter().flat_map(|(key, what)| {
                labeled_lines(
                    Span::styled(format!(" {key:<key_w$}"), Style::new().fg(theme.accent)),
                    what,
                    Style::new().fg(theme.fg),
                    desc_w,
                )
            }));
        }
        lines
    };
    let inner_w = usize::from(width).saturating_sub(2);
    let mut lines = lines_at(inner_w);
    let room = clamp_u16(lines.len()).min(area.height.saturating_sub(3));
    // Outgrowing the frame, it takes a column for its bar: one more when the
    // frame has it, else one of its own, re-wrapped.
    let bar = lines.len() > usize::from(room);
    let width = if !bar {
        width
    } else if width < area.width {
        width + viewport::BAR_W
    } else {
        lines = lines_at(inner_w.saturating_sub(usize::from(viewport::BAR_W)));
        width
    };
    let height = room.saturating_add(3).min(area.height);
    let room = height.saturating_sub(3);
    let modal = centered(area, width, height);
    frame.render_widget(Clear, modal);
    let block = Block::bordered()
        .border_style(theme.chrome())
        .style(Style::new().fg(theme.fg).bg(theme.panel))
        .title_top(Line::from(Span::styled(
            labels::HELP_TITLE,
            theme.tab_active(),
        )));
    let inner = block.inner(modal);
    frame.render_widget(block, modal);
    let (inner, filter_line) = filter.carve(inner);
    let caret = filter.draw(frame, filter_line, (kept_rows, total_rows), theme);
    let mut place = scroll.0.get();
    let shown = place.show(lines.len(), room);
    scroll.0.set(place);
    let (list, bar) = viewport::split(inner, bar);
    frame.render_widget(Paragraph::new(lines[shown].to_vec()), list);
    // The border says which lines show while not all of them do, and the
    // keys that move them, which give way first.
    let rest = place.draw(frame, modal, bar, theme);
    if place.overflows() && usize::from(rest.width) >= display_width(SCROLL_HINT) {
        frame.render_widget(
            Paragraph::new(Span::styled(SCROLL_HINT, theme.dim_text())).right_aligned(),
            rest,
        );
    }
    caret
}

/// The help's scroll keys, on its bottom border while it overflows.
const SCROLL_HINT: &str = " ↑/↓ ";

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
            draw_overlays(frame, &UiState::default(), &chrome, &theme);
        });
        let rows: Vec<&str> = rendered.lines().collect();
        assert!(
            rows[0].starts_with("┌ 1 Networks"),
            "tab bar covered: {:?}",
            rows[0]
        );
        assert!(
            rows[23].starts_with("└ ▼"),
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
            draw_overlays(frame, &UiState::default(), &chrome, &Theme::default_dark());
        });
    }

    /// A frame tall enough for every binding: no bar, and no count — the
    /// help has no cursor to place.
    #[test]
    fn golden_help_overlay_fits_a_tall_frame() {
        let mut chrome = chrome();
        chrome.update(&Action::ToggleHelp, now());
        assert_golden("chrome_help_fits", 100, 44, |frame| {
            draw_frame(
                frame,
                &UiState::default(),
                &chrome,
                &Theme::default_dark(),
                now(),
            );
            draw_overlays(frame, &UiState::default(), &chrome, &Theme::default_dark());
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
                draw_overlays(frame, &UiState::default(), chrome, &theme);
            })
        };
        let top = draw(&chrome);
        assert!(top.contains("add server"), "{top}");
        assert!(!top.contains("struck through"), "{top}");
        assert!(chrome.update(&Action::ScrollHelp(i16::MAX), now()));
        assert_golden("chrome_help_scrolled", 80, 24, |frame| {
            draw_frame(frame, &UiState::default(), &chrome, &theme, now());
            draw_overlays(frame, &UiState::default(), &chrome, &theme);
        });
        let end = draw(&chrome);
        assert!(end.contains("struck through"), "{end}");
        let rows: Vec<&str> = end.lines().collect();
        assert!(rows[0].starts_with("┌ 1 Networks"), "{}", rows[0]);
        assert!(rows[23].starts_with("└ ▼"), "{}", rows[23]);
        assert!(
            !chrome.update(&Action::ScrollHelp(1), now()),
            "the end holds"
        );
        assert!(chrome.update(&Action::ScrollHelp(i16::MIN), now()));
        assert_eq!(draw(&chrome), top);
    }

    /// While help is up the arrows and page keys scroll it, a typed letter
    /// narrows it, and `Esc` takes the text before it takes the overlay.
    #[test]
    fn help_scrolls_by_the_arrows_and_a_typed_letter_filters() {
        use ratatui::crossterm::event::KeyCode;
        let mut chrome = chrome();
        chrome.update(&Action::ToggleHelp, now());
        let map = |chrome: &ChromeState, code| crate::input::map_key(chrome, press(code));
        assert!(matches!(
            map(&chrome, KeyCode::Down),
            Some(Action::ScrollHelp(1))
        ));
        assert!(matches!(
            map(&chrome, KeyCode::End),
            Some(Action::ScrollHelp(i16::MAX))
        ));
        let Some(typed) = map(&chrome, KeyCode::Char('w')) else {
            panic!("a letter goes to the filter");
        };
        chrome.update(&typed, now());
        assert!(!chrome.help_filter.is_empty());
        assert!(matches!(
            map(&chrome, KeyCode::Esc),
            Some(Action::HelpKey(_))
        ));
        assert!(matches!(
            map(&chrome, KeyCode::Char('?')),
            Some(Action::HelpKey(_)),
        ));
        let clear = map(&chrome, KeyCode::Esc).expect("Esc clears");
        chrome.update(&clear, now());
        assert!(matches!(
            map(&chrome, KeyCode::Esc),
            Some(Action::DismissOverlay)
        ));
    }

    /// Help opens on the tab it came from.
    #[test]
    fn help_opens_on_the_current_tabs_keys() {
        let theme = Theme::default_dark();
        let mut chrome = chrome();
        chrome.active = crate::view::ViewId::Transfers;
        chrome.update(&Action::ToggleHelp, now());
        let shown = crate::golden::render_to_lines(80, 24, |frame| {
            draw_frame(frame, &UiState::default(), &chrome, &theme, now());
            draw_overlays(frame, &UiState::default(), &chrome, &theme);
        });
        assert!(shown.contains("clear all completed"), "{shown}");
        assert!(!shown.contains("add server"), "{shown}");
    }

    /// Typing keeps the rows that hold it, in every table, words too.
    #[test]
    fn typing_finds_a_key_and_a_word() {
        let theme = Theme::default_dark();
        let mut chrome = chrome();
        chrome.update(&Action::ToggleHelp, now());
        for letter in "struck".chars() {
            let key = Action::HelpKey(press(ratatui::crossterm::event::KeyCode::Char(letter)));
            chrome.update(&key, now());
        }
        let shown = crate::golden::render_to_lines(80, 24, |frame| {
            draw_frame(frame, &UiState::default(), &chrome, &theme, now());
            draw_overlays(frame, &UiState::default(), &chrome, &theme);
        });
        assert!(shown.contains("cancelled"), "{shown}");
        assert!(!shown.contains("add server"), "{shown}");
    }
}
