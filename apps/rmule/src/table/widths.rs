//! **Greedy width**: a table's column budget. One line per row (ADR-0119), so
//! a pane that cannot hold every column takes columns away, in the table's
//! stated order, rather than squeezing a value.

use crate::words::labels as words;
use crate::wrap::display_width;

/// What a table declares about its columns for [`greedy_widths`].
pub(crate) struct TableColumns<'a> {
    /// Each column's floor: the width it is shown at or not at all. The greedy
    /// column's is the room it keeps before other columns give way to it.
    pub floors: &'a [usize],
    /// Each column's header as drawn — its label, plus the sort's arrow on
    /// the column holding it. A header is never split: no column is given
    /// less than its header.
    pub headers: &'a [usize],
    /// The greedy column, which absorbs the slack. It holds the free text;
    /// every other column holds bounded content and is served first, from
    /// `wants`.
    pub flex: usize,
    /// A second free-text column levelled with `flex`: they share the slack,
    /// as equal as their floors allow.
    pub flex_pair: Option<usize>,
    /// Each column's widest value drawn now, in cells and capped by the table,
    /// or `0` (and an empty slice) for a column with nothing to ask. Slack goes
    /// to these before it goes to `flex`, the column that gives way last
    /// first, so an endpoint, a phase or a rate is whole whenever the pane has
    /// room for it and the free-text column gets what remains.
    pub wants: &'a [usize],
    /// The order columns give way in: the first listed goes first. The greedy
    /// column never gives way.
    pub give_way: &'a [usize],
}

/// Column widths for a row of `total` cells with `gap` blank cells between
/// shown columns. Every shown column keeps its floor and its header; columns
/// give way in the table's order until the rest fit, and one that gave way is
/// `0` wide, draws nothing and costs no gap. The table says which ([`gave_way`])
/// and the selected row's values ride the Off-screen line. Slack goes to what
/// the bounded columns want, then to the greedy column. Only a pane too narrow
/// for the greedy column's own floor once every other column has gone narrows
/// that column.
pub(crate) fn greedy_widths(total: usize, table: &TableColumns<'_>, gap: usize) -> Vec<usize> {
    let columns = table.floors.len();
    let mut out: Vec<usize> = (0..columns)
        .map(|index| {
            let header = table.headers.get(index).copied().unwrap_or(1);
            table.floors[index].max(header).max(1)
        })
        .collect();
    let cost = |widths: &[usize]| {
        let shown = widths.iter().filter(|width| **width > 0).count();
        widths.iter().sum::<usize>() + gap * shown.saturating_sub(1)
    };
    for &index in table.give_way {
        if cost(&out) <= total {
            break;
        }
        if index != table.flex && index < columns {
            out[index] = 0;
        }
    }
    let used = cost(&out);
    if used > total {
        out[table.flex] = out[table.flex].saturating_sub(used - total).max(1);
        return out;
    }
    let mut slack = total - used;
    let served = table
        .give_way
        .iter()
        .rev()
        .copied()
        .chain((0..columns).filter(|index| !table.give_way.contains(index)));
    for index in served.filter(|index| *index != table.flex && *index < columns) {
        if out[index] == 0 || Some(index) == table.flex_pair {
            continue;
        }
        let want = table.wants.get(index).copied().unwrap_or(0);
        let raise = want.saturating_sub(out[index]).min(slack);
        out[index] += raise;
        slack -= raise;
    }
    out[table.flex] += slack;
    if let Some(pair) = table.flex_pair.filter(|pair| out[*pair] > 0) {
        let shared = out[table.flex] + out[pair];
        let even = shared / 2;
        let floor = out[pair];
        out[pair] = even.max(floor);
        out[table.flex] = shared - out[pair];
    }
    out
}

/// The labels of the columns that gave way at `widths`, left to right;
/// empty when every column is shown.
pub(crate) fn gave_way<'a>(
    labels: impl IntoIterator<Item = &'a str>,
    widths: &[usize],
) -> Vec<&'a str> {
    labels
        .into_iter()
        .zip(widths)
        .filter(|(_, width)| **width == 0)
        .map(|(label, _)| label)
        .collect()
}

/// What to say about the columns that gave way, in at most `room` cells: the
/// columns by name when they fit, else how many, so the note is never cut.
/// `None` when every column shows, or `room` holds no form at all.
pub(crate) fn gave_way_note(hidden: &[&str], room: usize) -> Option<String> {
    if hidden.is_empty() {
        return None;
    }
    words::gave_way_notes(hidden)
        .into_iter()
        .find(|note| display_width(note) <= room)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table<'a>(
        floors: &'a [usize],
        give_way: &'a [usize],
        wants: &'a [usize],
    ) -> TableColumns<'a> {
        TableColumns {
            floors,
            headers: &[],
            flex: 0,
            flex_pair: None,
            wants,
            give_way,
        }
    }

    #[test]
    fn the_greedy_column_takes_the_slack() {
        assert_eq!(
            greedy_widths(40, &table(&[10, 5, 5], &[2, 1], &[]), 1),
            [28, 5, 5]
        );
    }

    #[test]
    fn bounded_columns_are_served_what_they_show_before_the_name() {
        assert_eq!(
            greedy_widths(40, &table(&[10, 5, 5], &[2, 1], &[0, 9, 7]), 1),
            [22, 9, 7]
        );
    }

    /// The name keeps its floor: bounded columns go, in the stated order,
    /// rather than the name shrinking to hold them.
    #[test]
    fn columns_give_way_in_order_before_the_name_goes_under_its_floor() {
        assert_eq!(
            greedy_widths(30, &table(&[20, 5, 5], &[2, 1], &[]), 1),
            [24, 5, 0]
        );
        assert_eq!(
            greedy_widths(22, &table(&[20, 5, 5], &[2, 1], &[]), 1),
            [22, 0, 0]
        );
    }

    #[test]
    fn a_column_is_never_narrower_than_its_header() {
        let table = TableColumns {
            headers: &[4, 10, 3],
            ..table(&[8, 3, 3], &[2, 1], &[])
        };
        assert_eq!(greedy_widths(30, &table, 1), [15, 10, 3]);
    }

    #[test]
    fn a_pane_under_the_names_floor_narrows_the_name_alone() {
        assert_eq!(
            greedy_widths(12, &table(&[20, 5, 5], &[2, 1], &[]), 1),
            [12, 0, 0]
        );
    }

    #[test]
    fn a_pair_of_free_text_columns_levels_the_slack() {
        let table = TableColumns {
            flex_pair: Some(1),
            ..table(&[10, 8, 5], &[1, 2], &[])
        };
        assert_eq!(greedy_widths(40, &table, 1), [17, 16, 5]);
    }

    #[test]
    fn the_note_names_the_columns_then_counts_them() {
        let hidden = ["Size", "ETA"];
        assert_eq!(
            gave_way_note(&hidden, 40).as_deref(),
            Some(" too narrow to show: Size, ETA ")
        );
        assert_eq!(
            gave_way_note(&hidden, 21).as_deref(),
            Some(" 2 columns not shown ")
        );
        assert_eq!(gave_way_note(&hidden, 10).as_deref(), Some(" 2 hidden "));
        assert_eq!(gave_way_note(&hidden, 5), None);
        assert_eq!(gave_way_note(&[], 40), None);
    }
}
