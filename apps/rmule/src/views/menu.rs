//! The one row menu: every table's action list is these items, these keys and
//! this drawing. An item is enabled, or greyed with its reason, which the
//! cursor skips: the menu never hides an action the operator might look for
//! and never offers one that would be rejected.
//!
//! The list wraps at its ends, `m`, `q` and `Esc` close it, `Enter` runs the
//! item the cursor is on, and an item's own key, which it shows, runs it from
//! the open menu as it does from the table. A click runs an item and a click
//! outside closes the menu; [`Place`] remembers where the last draw put it.

use std::cell::{Cell, RefCell};

use ratatui::Frame;
use ratatui::crossterm::event::KeyCode;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use super::modal::{ListPlaced, Modal};
use crate::row_selection::MARKER;
use crate::row_selection::viewport::Viewport;
use crate::table::cut_middle;
use crate::table_sort::RowMove;
use crate::theme::Theme;
use crate::words::app as words;
use crate::wrap::{clamp_u16, display_width, labeled_lines};

/// The narrowest a menu is drawn, so its title has room.
const MIN_WIDTH: usize = 48;
/// The cells around an item's text: the marker, and the border on each side.
const CHROME: usize = 4;

/// One entry of a menu.
pub(crate) struct Item<A> {
    /// What it does.
    pub label: String,
    /// The key that does it from the table, which it wears as `(c)`.
    pub key: Option<char>,
    /// Why it cannot run now: it is greyed with this, and the cursor skips it.
    pub reason: Option<String>,
    /// What it runs.
    pub action: A,
}

impl<A> Item<A> {
    pub(crate) fn new(label: impl Into<String>, action: A) -> Self {
        Self {
            label: label.into(),
            key: None,
            reason: None,
            action,
        }
    }

    /// It wears and answers to `key`.
    #[must_use]
    pub(crate) const fn keyed(mut self, key: char) -> Self {
        self.key = Some(key);
        self
    }

    /// Greyed with `reason`, when there is one.
    #[must_use]
    pub(crate) fn greyed(mut self, reason: Option<impl Into<String>>) -> Self {
        self.reason = reason.map(Into::into);
        self
    }

    fn text(&self) -> String {
        let label = match self.key {
            Some(key) => words::keyed_item(&self.label, key),
            None => self.label.clone(),
        };
        match &self.reason {
            Some(reason) => format!("{label}  {reason}"),
            None => label,
        }
    }
}

/// What a key or a click asks of an open menu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Asked {
    /// Close it.
    Close,
    /// Rest the cursor on this item.
    Move(usize),
    /// Run this item.
    Run(usize),
    /// Nothing: it is modal, so the key goes no further.
    Nothing,
}

/// Where a fresh menu rests: the first enabled item.
#[must_use]
pub(crate) fn first_enabled<A>(items: &[Item<A>]) -> usize {
    items
        .iter()
        .position(|item| item.reason.is_none())
        .unwrap_or(0)
}

/// The enabled item `delta` steps from `cursor`, wrapping past the ends and
/// skipping what is greyed; `cursor` when nothing else is enabled.
#[must_use]
pub(crate) fn step<A>(items: &[Item<A>], cursor: usize, delta: isize) -> usize {
    let count = items.len();
    let forward = delta >= 0;
    (1..count)
        .map(|steps| {
            if forward {
                (cursor + steps) % count
            } else {
                (cursor + count - steps) % count
            }
        })
        .find(|index| items[*index].reason.is_none())
        .unwrap_or(cursor)
}

/// The one reading of a key over an open menu.
#[must_use]
pub(crate) fn key<A>(items: &[Item<A>], cursor: usize, code: KeyCode) -> Asked {
    if let Some(movement) = RowMove::of(code) {
        return Asked::Move(match movement {
            RowMove::Step(delta) | RowMove::Page(delta) => step(items, cursor, delta),
            RowMove::First => first_enabled(items),
            RowMove::Last => step(items, first_enabled(items), -1),
        });
    }
    match code {
        KeyCode::Esc | KeyCode::Char('q' | 'm') => Asked::Close,
        KeyCode::Enter if items.get(cursor).is_some_and(|item| item.reason.is_none()) => {
            Asked::Run(cursor)
        }
        KeyCode::Char(typed) => items
            .iter()
            .position(|item| item.key == Some(typed) && item.reason.is_none())
            .map_or(Asked::Nothing, Asked::Run),
        _ => Asked::Nothing,
    }
}

/// What a menu keeps between frames: what part of it is on screen, in a frame
/// too short for it, and where the last draw put it, for a click.
#[derive(Debug, Default)]
pub(crate) struct Place {
    viewport: Cell<Viewport>,
    placed: RefCell<ListPlaced>,
}

impl Place {
    /// Forget the last menu: a new one opens at its top.
    pub(crate) fn reset(&self) {
        self.viewport.take();
        self.placed.take();
    }

    /// What a click at (`column`, `row`) asks: the enabled item under it runs,
    /// a greyed one or the border does nothing, and outside the menu closes it.
    #[must_use]
    pub(crate) fn click<A>(&self, items: &[Item<A>], column: u16, row: u16) -> Asked {
        let placed = self.placed.borrow();
        if !placed.contains(column, row) {
            return Asked::Close;
        }
        match placed.item_at(column, row) {
            Some(index) if items.get(index).is_some_and(|item| item.reason.is_none()) => {
                Asked::Run(index)
            }
            _ => Asked::Nothing,
        }
    }
}

/// `name` fit to a menu's or a confirm's title, as a Middle cut.
#[must_use]
pub(crate) fn title(name: &str, width: u16) -> String {
    let room = usize::from(width).saturating_sub(CHROME);
    format!(" {} ", cut_middle(name, room))
}

/// Draw the menu centered in `area`, titled `name`, its cursor on `cursor`.
pub(crate) fn draw<A>(
    frame: &mut Frame,
    area: Rect,
    (name, items, cursor): (&str, &[Item<A>], usize),
    theme: &Theme,
    place: &Place,
) {
    // Greedy width: wide enough for every item whole, clamped to the frame;
    // whatever still overflows wraps under its marker.
    let natural = items
        .iter()
        .map(|item| display_width(&item.text()) + CHROME)
        .max()
        .unwrap_or(0)
        .max(MIN_WIDTH);
    let width = clamp_u16(natural).min(area.width);
    let rows = |width: u16| -> Vec<Vec<Line<'static>>> {
        let text_w = usize::from(width).saturating_sub(CHROME).max(1);
        items
            .iter()
            .enumerate()
            .map(|(index, item)| {
                let on = index == cursor && item.reason.is_none();
                let style = if item.reason.is_some() {
                    theme.dim_text()
                } else if on {
                    Style::new().fg(theme.accent).add_modifier(Modifier::BOLD)
                } else {
                    Style::new().fg(theme.fg)
                };
                let marker = if on { MARKER } else { "  " };
                labeled_lines(Span::styled(marker, style), &item.text(), style, text_w)
            })
            .collect()
    };
    let placed = Modal::new(title(name, width), theme).draw_list(
        frame,
        area,
        (width, cursor),
        theme,
        &place.viewport,
        rows,
    );
    *place.placed.borrow_mut() = placed;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn items() -> Vec<Item<u8>> {
        vec![
            Item::new("Pause", 0).keyed('p'),
            Item::new("Cancel…", 1).greyed(Some("completed")).keyed('x'),
            Item::new("Details", 2),
            Item::new("Preview", 3).keyed('v'),
        ]
    }

    #[test]
    fn the_cursor_wraps_at_both_ends_and_skips_what_is_greyed() {
        let items = items();
        assert_eq!(step(&items, 0, 1), 2);
        assert_eq!(step(&items, 3, 1), 0);
        assert_eq!(step(&items, 0, -1), 3);
        assert_eq!(step(&items, 2, -1), 0);
    }

    #[test]
    fn every_menu_closes_alike_and_runs_an_item_by_its_own_key() {
        let items = items();
        for code in [KeyCode::Esc, KeyCode::Char('q'), KeyCode::Char('m')] {
            assert_eq!(key(&items, 0, code), Asked::Close);
        }
        assert_eq!(key(&items, 0, KeyCode::Enter), Asked::Run(0));
        assert_eq!(key(&items, 0, KeyCode::Char('v')), Asked::Run(3));
        assert_eq!(
            key(&items, 0, KeyCode::Char('x')),
            Asked::Nothing,
            "a greyed item's key runs nothing"
        );
        assert_eq!(key(&items, 0, KeyCode::Char('G')), Asked::Move(3));
    }

    #[test]
    fn a_click_runs_an_item_and_outside_closes_and_a_greyed_row_does_nothing() {
        let items = items();
        let place = Place::default();
        let theme = Theme::default_dark();
        crate::golden::render_to_lines(80, 24, |frame| {
            draw(
                frame,
                frame.area(),
                ("bunny.mp4", &items, 0),
                &theme,
                &place,
            );
        });
        let line_of = |index: u16| {
            let top = (24 - 6) / 2;
            top + 1 + index
        };
        assert_eq!(place.click(&items, 30, line_of(2)), Asked::Run(2));
        assert_eq!(place.click(&items, 30, line_of(1)), Asked::Nothing);
        assert_eq!(place.click(&items, 1, 1), Asked::Close);
    }
}
