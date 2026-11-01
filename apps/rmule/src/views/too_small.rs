//! The screen for a terminal no view fits: it says so and what it takes, in
//! place of panes that would vanish without a word. While it is up only the
//! way out answers, so no key acts on a row nobody can see.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::widgets::Paragraph;

use crate::theme::Theme;
use crate::words::app::too_small;
use crate::wrap::wrapped_lines;

/// The narrowest terminal the views are laid out for.
pub(crate) const MIN_WIDTH: u16 = 60;
/// The shortest: the Networks tab's server table above its log and Kad panes.
pub(crate) const MIN_HEIGHT: u16 = 20;

/// Whether a terminal of `area` is under the minimum.
#[must_use]
pub(crate) const fn holds(area: Rect) -> bool {
    area.width < MIN_WIDTH || area.height < MIN_HEIGHT
}

/// Say so across the whole terminal.
pub(crate) fn draw(frame: &mut Frame, theme: &Theme) {
    let area = frame.area();
    let text = too_small((area.width, area.height), (MIN_WIDTH, MIN_HEIGHT));
    let lines = wrapped_lines(&text, usize::from(area.width), theme.dim_text());
    frame.render_widget(Paragraph::new(lines).style(theme.base()), area);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_minimum_is_the_first_size_that_fits() {
        assert!(!holds(Rect::new(0, 0, MIN_WIDTH, MIN_HEIGHT)));
        assert!(holds(Rect::new(0, 0, MIN_WIDTH - 1, MIN_HEIGHT)));
        assert!(holds(Rect::new(0, 0, MIN_WIDTH, MIN_HEIGHT - 1)));
    }

    #[test]
    fn it_says_the_size_and_the_way_out_at_every_size_down_to_a_sliver() {
        for (width, height) in [(59, 40), (40, 12), (12, 4), (10, 3), (1, 1)] {
            let drawn = crate::golden::render_to_lines(width, height, |frame| {
                draw(frame, &Theme::default_dark());
            });
            if width >= 40 {
                assert!(drawn.contains("60×20"), "{drawn}");
                assert!(drawn.contains("q quits"), "{drawn}");
            }
        }
    }
}
