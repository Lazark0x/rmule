//! A pane's top border: its title on the left, its key hint on the right, and
//! what gives way when the border is too narrow for both. Nothing is
//! cut: whole parts give way in a stated order — the hint's, last first, then
//! the title's, last first — so a narrow pane reads `Servers (3)`, never
//! `Ser a add…`. A title's parts are its ` · `-separated clauses; a hint's are
//! its keys ([`hints::line`]).

use crate::words::hints;
use crate::wrap::display_width;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Block;

/// The separator between a title's clauses.
const DOT: &str = " · ";

/// One title or hint, split into the parts that give way whole.
struct Parts<'a> {
    parts: Vec<&'a str>,
    joiner: &'static str,
}

impl<'a> Parts<'a> {
    fn title(text: &'a str) -> Self {
        Self::split(text.trim(), DOT)
    }

    fn hint(text: &'a str) -> Self {
        Self::split(text.trim(), hints::GAP)
    }

    fn split(text: &'a str, joiner: &'static str) -> Self {
        let parts = if text.is_empty() {
            Vec::new()
        } else {
            text.split(joiner).collect()
        };
        Self { parts, joiner }
    }

    /// The border text: the kept parts, padded by a space each side; empty
    /// once every part gave way.
    fn text(&self) -> String {
        if self.parts.is_empty() {
            String::new()
        } else {
            format!(" {} ", self.parts.join(self.joiner))
        }
    }

    fn width(&self) -> usize {
        display_width(&self.text())
    }
}

/// Fit `title` and `hint` into a border `width` columns wide, corners
/// included: the padded texts to draw, either empty once it gave way whole.
#[must_use]
pub(crate) fn fit_titles(width: u16, title: &str, hint: &str) -> (String, String) {
    fit(width, title, hint, false)
}

/// The fit, with the hint's first key outlasting every title clause but the
/// first when `first_key` holds.
fn fit(width: u16, title: &str, hint: &str, first_key: bool) -> (String, String) {
    let room = usize::from(width).saturating_sub(2);
    let mut title = Parts::title(title);
    let mut hint = Parts::hint(hint);
    loop {
        let (t, h) = (title.width(), hint.width());
        let gap = usize::from(t > 0 && h > 0);
        if t + h + gap <= room {
            break;
        }
        if first_key && hint.parts.len() == 1 && title.parts.len() > 1 {
            title.parts.pop();
        } else if hint.parts.pop().is_none() && title.parts.pop().is_none() {
            break;
        }
    }
    (title.text(), hint.text())
}

/// `block` with `title` and `hint` fitted into a border `width` wide.
#[must_use]
pub(crate) fn titled<'a>(
    block: Block<'a>,
    width: u16,
    (title, title_style): (&str, Style),
    (hint, hint_style): (&str, Style),
) -> Block<'a> {
    let (title, hint) = fit_titles(width, title, hint);
    with_titles(block, (title, title_style), (hint, hint_style))
}

/// [`titled`] for a pane whose first key is how to act on it: that key stays
/// after the title's later clauses have given way.
#[must_use]
pub(crate) fn titled_first_key<'a>(
    block: Block<'a>,
    width: u16,
    (title, title_style): (&str, Style),
    (hint, hint_style): (&str, Style),
) -> Block<'a> {
    let (title, hint) = fit(width, title, hint, true);
    with_titles(block, (title, title_style), (hint, hint_style))
}

fn with_titles<'a>(
    block: Block<'a>,
    (title, title_style): (String, Style),
    (hint, hint_style): (String, Style),
) -> Block<'a> {
    let mut block = block;
    if !title.is_empty() {
        block = block.title_top(Line::from(Span::styled(title, title_style)));
    }
    if !hint.is_empty() {
        block = block.title_top(Line::from(Span::styled(hint, hint_style)).right_aligned());
    }
    block
}

#[cfg(test)]
mod tests {
    use super::{fit, fit_titles};

    #[test]
    fn the_first_key_outlasts_the_title_clauses_after_the_first() {
        let (title, hint) = fit(
            44,
            " Results · 228 · server done · Kad done ",
            " Enter menu  [ ] search  x close ",
            true,
        );
        assert_eq!(title, " Results · 228 · server done ");
        assert_eq!(hint, " Enter menu ");
    }

    #[test]
    fn a_border_with_room_keeps_every_part() {
        assert_eq!(
            fit_titles(
                60,
                " Servers (3) · 10.0.0.1:4661 HighID ",
                " a add · U update "
            ),
            (
                " Servers (3) · 10.0.0.1:4661 HighID ".to_string(),
                " a add · U update ".to_string()
            )
        );
    }

    /// The hint gives way before the title does, key by key, last first.
    #[test]
    fn the_hint_gives_way_first_last_key_first() {
        let (title, hint) = fit_titles(
            36,
            " Servers (3) · not connected ",
            " a add · U update · m menu ",
        );
        assert_eq!(title, " Servers (3) · not connected ");
        assert_eq!(hint, "");
        let (title, hint) = fit_titles(46, " Uploads · all ", " s sort  S reverse ");
        assert_eq!(
            (title.as_str(), hint.as_str()),
            (" Uploads · all ", " s sort  S reverse ")
        );
        let (title, hint) = fit_titles(28, " Uploads · all ", " s sort  S reverse ");
        assert_eq!(
            (title.as_str(), hint.as_str()),
            (" Uploads · all ", " s sort ")
        );
    }

    /// With the hint gone the title's clauses give way, last first, and a
    /// clause is never cut: no `Ser a add…` or `Uploads · ac`.
    #[test]
    fn the_title_gives_way_in_whole_clauses_never_mid_word() {
        let (title, hint) = fit_titles(18, " Servers (3) · not connected ", " a add ");
        assert_eq!((title.as_str(), hint.as_str()), (" Servers (3) ", ""));
        let (title, _) = fit_titles(14, " Uploads · active only ", "");
        assert_eq!(title, " Uploads ");
        let (title, _) = fit_titles(6, " Uploads ", "");
        assert_eq!(title, "", "a clause that does not fit gives way whole");
    }
}
