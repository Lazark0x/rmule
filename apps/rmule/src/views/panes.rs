//! How a view shares its content rect between two panes: stacked, side by side
//! where the terminal is wide, a pane with nothing to list small, and either
//! one zoomed to the whole rect while the operator reads it.

use ratatui::layout::{Constraint, Layout, Rect};

/// The width from which two panes stand side by side: each still holds a table
/// at the canonical eighty cells.
const SIDE_BY_SIDE_FROM: u16 = 160;

/// Which pane a zoomed view shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Zoomed {
    First,
    Second,
}

/// `area` split between two panes, the first taking `share` percent of it. A
/// second pane with nothing to list takes the `idle` lines it says that in,
/// wherever the panes stack. A zoomed pane takes all of it and the other none,
/// which draws nothing and takes no click.
#[must_use]
pub(crate) fn split(
    area: Rect,
    share: u16,
    idle: Option<u16>,
    zoomed: Option<Zoomed>,
) -> (Rect, Rect) {
    match zoomed {
        Some(Zoomed::First) => return (area, Rect::default()),
        Some(Zoomed::Second) => return (Rect::default(), area),
        None => {}
    }
    let shares = [Constraint::Percentage(share), Constraint::Min(0)];
    if area.width >= SIDE_BY_SIDE_FROM {
        let [first, second] = Layout::horizontal(shares).areas(area);
        return (first, second);
    }
    let [first, second] = match idle {
        Some(lines) => {
            Layout::vertical([Constraint::Min(0), Constraint::Length(lines)]).areas(area)
        }
        None => Layout::vertical(shares).areas(area),
    };
    (first, second)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TALL: Rect = Rect::new(0, 0, 78, 22);

    #[test]
    fn panes_stack_by_share_and_stand_side_by_side_from_160_cells() {
        let (first, second) = split(TALL, 62, None, None);
        assert_eq!((first.height, second.height), (14, 8));
        assert_eq!(first.width, 78);
        let (first, second) = split(Rect::new(0, 0, 200, 58), 62, None, None);
        assert_eq!((first.width, second.width), (124, 76));
        assert_eq!((first.height, second.height), (58, 58));
    }

    #[test]
    fn a_pane_with_nothing_to_list_takes_only_the_lines_it_says_so_in() {
        let (first, second) = split(TALL, 62, Some(3), None);
        assert_eq!((first.height, second.height), (19, 3));
    }

    #[test]
    fn a_zoomed_pane_takes_the_rect_and_the_other_draws_nothing() {
        let (first, second) = split(TALL, 62, None, Some(Zoomed::Second));
        assert!(first.is_empty());
        assert_eq!(second, TALL);
    }
}
