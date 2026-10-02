//! The **Table Sort** (ADR-0070): the one column a table is
//! ordered by and its direction, and everything that follows from it — the
//! order rows render in, the arrow in the active header, which column a header
//! click lands on, the cursor that stays on its row while rows re-order, and
//! the text the sort is kept as across runs.
//!
//! A table adopts it by describing itself once as a [`SortedTable`] — its
//! visible columns, each one's [`ColumnKind`], how a row yields a column's
//! [`SortValue`], and the row's identity. Everything else is here, so every
//! table sorts, ties, folds names and places its cursor the same way.
//!
//! A column's order may be a rank before it is a number: a table can group its
//! rows by what they are (a download's activity) ahead of the column's value,
//! and the groups keep their order in both directions — `S` reverses the
//! number inside each group, never the groups.
//!
//! The order is total: rows the sort column holds equal fall to the **Tie
//! Chain** (name ascending, then identity), which reversing never reverses. A
//! set therefore renders one way whatever order core published it in.

use std::borrow::Cow;
use std::cmp::Ordering;

pub use cursor::{RowCursor, RowMove};
pub use stored::TableSorts;

mod cursor;
mod keys;
mod name;
mod stored;
#[cfg(test)]
mod tests;

/// Which way a column's values run down the table.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Direction {
    /// Smallest (or alphabetically first) at the top.
    #[default]
    Ascending,
    /// Largest (or alphabetically last) at the top.
    Descending,
}

impl Direction {
    /// The other direction — what `S` does.
    #[must_use]
    pub const fn reversed(self) -> Self {
        match self {
            Self::Ascending => Self::Descending,
            Self::Descending => Self::Ascending,
        }
    }

    /// The glyph the active header carries.
    #[must_use]
    pub const fn arrow(self) -> char {
        match self {
            Self::Ascending => '▲',
            Self::Descending => '▼',
        }
    }
}

/// What a column holds, which fixes its **Natural Direction**.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColumnKind {
    /// Words that compare as words: names, addresses. First sorted ascending.
    Text,
    /// A word that stands for a rank (a type, a status, a priority): ordered
    /// by the rank, never by the label, and first sorted ascending like the
    /// words it stands for.
    Rank,
    /// Amounts: sizes, counts, rates. First sorted descending — the biggest is
    /// what the operator reaches for.
    Quantity,
}

impl ColumnKind {
    /// Whether a column of this kind sits right-aligned: amounts do, words
    /// stay left.
    #[must_use]
    pub const fn right_aligned(self) -> bool {
        matches!(self, Self::Quantity)
    }

    /// The direction a column takes when it first receives the sort.
    #[must_use]
    pub const fn natural_direction(self) -> Direction {
        match self {
            Self::Text | Self::Rank => Direction::Ascending,
            Self::Quantity => Direction::Descending,
        }
    }
}

/// One cell's value as the sort compares it — never its rendered text, so
/// `9.5 MB` does not sort after `10.0 GB`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SortValue<'a> {
    /// Compared case-folded and accent-folded, digit runs as numbers.
    Text(Cow<'a, str>),
    /// Compared as a number.
    Quantity(u64),
    /// `part / whole`, compared as the exact ratio — a share (done, held)
    /// whose rendering rounds. A zero `whole` compares as zero.
    Fraction {
        /// The numerator.
        part: u64,
        /// The denominator.
        whole: u64,
    },
    /// Two figures compared in order: `first`, then `second` — a cell that
    /// ties on its headline number and breaks the tie on another.
    Pair {
        /// Compared first.
        first: u64,
        /// Compared when `first` ties.
        second: u64,
    },
}

/// What a table says of one column, once: the stored key, the header text and
/// what the column holds. The table lists its columns as these, so no
/// per-column fact is spread over parallel `match`es.
#[derive(Clone, Copy, Debug)]
pub struct ColumnSpec<C: 'static> {
    /// The column.
    pub column: C,
    /// Its stored key. Stable: renaming it forgets an installed sort.
    pub key: &'static str,
    /// The header's text, before any arrow.
    pub label: &'static str,
    /// What it holds, which fixes its Natural Direction.
    pub kind: ColumnKind,
}

impl<C> ColumnSpec<C> {
    /// A column's spec.
    #[must_use]
    pub const fn new(column: C, key: &'static str, label: &'static str, kind: ColumnKind) -> Self {
        Self {
            column,
            key,
            label,
            kind,
        }
    }
}

/// A table the sort can order: its visible columns and how a row answers for
/// each. Implemented once per table, on a marker type.
pub trait SortedTable {
    /// One row as the view holds it.
    type Row;
    /// One visible column.
    type Column: Copy + Eq + 'static;
    /// What makes a row itself across batches (file hash, download id, server
    /// endpoint): the last link of the Tie Chain and what the cursor binds to.
    type Identity: Ord + Clone;

    /// The table's entry in the stored [`TableSorts`]. Stable: renaming it
    /// forgets an installed sort.
    const TABLE: &'static str;
    /// The visible columns, left to right — the order `s` walks.
    const COLUMNS: &'static [ColumnSpec<Self::Column>];
    /// The name column: the default sort, and the Tie Chain's first link.
    /// Must be a [`ColumnKind::Text`] column.
    const NAME: Self::Column;

    /// The column's listing.
    ///
    /// # Panics
    /// When the table's [`Self::COLUMNS`] omits `column`, which a table must
    /// not: it lists every one.
    #[must_use]
    fn spec(column: Self::Column) -> &'static ColumnSpec<Self::Column> {
        Self::COLUMNS
            .iter()
            .find(|spec| spec.column == column)
            .expect("a table lists every one of its columns")
    }
    /// The column's stored key. Stable, like [`Self::TABLE`].
    #[must_use]
    fn column_key(column: Self::Column) -> &'static str {
        Self::spec(column).key
    }
    /// The header's text, before any arrow.
    #[must_use]
    fn label(column: Self::Column) -> &'static str {
        Self::spec(column).label
    }
    /// Text, rank or quantity.
    #[must_use]
    fn kind(column: Self::Column) -> ColumnKind {
        Self::spec(column).kind
    }
    /// The row's value in `column`; `None` when the row has none, which sorts
    /// last in both directions.
    fn value(column: Self::Column, row: &Self::Row) -> Option<SortValue<'_>>;
    /// The row's rank under `column`, compared before its value, lowest first
    /// in both directions. Every row ranks alike (`0`) unless a table says a
    /// column orders groups before numbers.
    fn rank(column: Self::Column, row: &Self::Row) -> u8 {
        let _ = (column, row);
        0
    }
    /// The row's identity.
    fn identity(row: &Self::Row) -> Self::Identity;
}

/// One table's sort: a column and a direction. The default is name ascending,
/// in every table.
pub struct TableSort<T: SortedTable> {
    column: T::Column,
    direction: Direction,
}

impl<T: SortedTable> Clone for TableSort<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: SortedTable> Copy for TableSort<T> {}

impl<T: SortedTable> std::fmt::Debug for TableSort<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("TableSort")
            .field(&T::column_key(self.column))
            .field(&self.direction)
            .finish()
    }
}

impl<T: SortedTable> PartialEq for TableSort<T> {
    fn eq(&self, other: &Self) -> bool {
        self.column == other.column && self.direction == other.direction
    }
}

impl<T: SortedTable> Default for TableSort<T> {
    fn default() -> Self {
        Self {
            column: T::NAME,
            direction: T::kind(T::NAME).natural_direction(),
        }
    }
}

impl<T: SortedTable> TableSort<T> {
    /// The column holding the sort.
    #[must_use]
    pub fn column(&self) -> T::Column {
        self.column
    }

    /// Its direction.
    #[must_use]
    pub fn direction(&self) -> Direction {
        self.direction
    }

    /// `s`: the next visible column, wrapping, in its Natural Direction.
    pub fn next_column(&mut self) {
        let at = T::COLUMNS
            .iter()
            .position(|spec| spec.column == self.column)
            .unwrap_or(0);
        self.take(T::COLUMNS[(at + 1) % T::COLUMNS.len()].column);
    }

    /// `S`: the same column, the other way.
    pub fn reverse(&mut self) {
        self.direction = self.direction.reversed();
    }

    /// A header click: sort by `column` in its Natural Direction, or reverse
    /// when `column` already holds the sort.
    pub fn click(&mut self, column: T::Column) {
        if column == self.column {
            self.reverse();
        } else {
            self.take(column);
        }
    }

    fn take(&mut self, column: T::Column) {
        self.column = column;
        self.direction = T::kind(column).natural_direction();
    }

    /// The arrow `column`'s header carries, if it holds the sort.
    #[must_use]
    pub fn arrow(&self, column: T::Column) -> Option<char> {
        (column == self.column).then(|| self.direction.arrow())
    }

    /// `rows`' indices in display order.
    #[must_use]
    pub fn order(&self, rows: &[T::Row]) -> Vec<usize> {
        // Decorate once: folding a name allocates, and a comparator would
        // otherwise fold each row O(log n) times.
        let keyed: Vec<Keyed<T::Identity>> = rows
            .iter()
            .map(|row| Keyed {
                rank: T::rank(self.column, row),
                sort: T::value(self.column, row).map(Key::from),
                name: T::value(T::NAME, row).map(Key::from),
                identity: T::identity(row),
            })
            .collect();
        let mut order: Vec<usize> = (0..rows.len()).collect();
        order.sort_by(|a, b| {
            let (a, b) = (&keyed[*a], &keyed[*b]);
            a.rank
                .cmp(&b.rank)
                .then_with(|| {
                    missing_last(a.sort.as_ref(), b.sort.as_ref(), |a, b| {
                        let ordering = a.cmp(b);
                        match self.direction {
                            Direction::Ascending => ordering,
                            Direction::Descending => ordering.reverse(),
                        }
                    })
                })
                .then_with(|| missing_last(a.name.as_ref(), b.name.as_ref(), Key::cmp))
                .then_with(|| a.identity.cmp(&b.identity))
        });
        order
    }

    /// The sort as the durable preference holds it.
    #[must_use]
    pub fn stored(&self) -> (&'static str, Direction) {
        (T::column_key(self.column), self.direction)
    }

    /// The table's sort out of the stored preferences; the default when the
    /// entry is absent or names a column this table no longer has.
    #[must_use]
    pub fn restore(sorts: &TableSorts) -> Self {
        sorts
            .get(T::TABLE)
            .and_then(|(key, direction)| {
                let column = T::COLUMNS.iter().find(|spec| spec.key == key)?.column;
                Some(Self { column, direction })
            })
            .unwrap_or_default()
    }
}

/// A sort value made comparable once, ahead of the sort.
struct Keyed<I> {
    rank: u8,
    sort: Option<Key>,
    name: Option<Key>,
    identity: I,
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Text(name::NameKey),
    Quantity(u64),
    Fraction(Ratio),
    Pair(u64, u64),
}

/// A ratio ordered by value, not by its terms: `2/4` equals `1/2`.
struct Ratio {
    part: u64,
    whole: u64,
}

impl Ord for Ratio {
    fn cmp(&self, other: &Self) -> Ordering {
        // Cross-multiplied in 128 bits: exact, and no u64 product overflows.
        (u128::from(self.part) * u128::from(other.whole))
            .cmp(&(u128::from(other.part) * u128::from(self.whole)))
    }
}

impl PartialOrd for Ratio {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Ratio {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Ratio {}

impl From<SortValue<'_>> for Key {
    fn from(value: SortValue<'_>) -> Self {
        match value {
            SortValue::Text(text) => Self::Text(name::NameKey::new(&text)),
            SortValue::Quantity(amount) => Self::Quantity(amount),
            SortValue::Fraction { whole: 0, .. } => Self::Fraction(Ratio { part: 0, whole: 1 }),
            SortValue::Fraction { part, whole } => Self::Fraction(Ratio { part, whole }),
            SortValue::Pair { first, second } => Self::Pair(first, second),
        }
    }
}

/// Order two optional values, a missing one last whatever `present` does.
fn missing_last<V>(a: Option<&V>, b: Option<&V>, present: impl Fn(&V, &V) -> Ordering) -> Ordering {
    match (a, b) {
        (Some(a), Some(b)) => present(a, b),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

/// Which column a click `x` cells right of the first column's left edge lands
/// on, for a header laid out as `widths` separated by `gap` blank cells. A
/// click in a gap lands on nothing.
#[must_use]
pub fn column_at(x: u16, widths: &[usize], gap: usize) -> Option<usize> {
    let mut left = 0usize;
    let x = usize::from(x);
    for (index, width) in widths.iter().enumerate() {
        if x < left + width {
            return Some(index);
        }
        left += width + gap;
        if x < left {
            return None;
        }
    }
    None
}

/// A header label with the sort's arrow when its column holds the sort.
#[must_use]
pub fn header_label(label: &str, arrow: Option<char>) -> String {
    match arrow {
        Some(arrow) => format!("{label} {arrow}"),
        None => label.to_string(),
    }
}

/// The cells [`header_label`] adds to a label: a space and the arrow.
const ARROW_W: usize = 2;

/// Each column's header width as [`header_label`] draws it under `sort`: the
/// label, and the arrow's cells on the column holding the sort. What the
/// greedy widths never split (`wrap::TableColumns::headers`).
#[must_use]
pub fn header_widths<T: SortedTable>(sort: &TableSort<T>) -> Vec<usize> {
    T::COLUMNS
        .iter()
        .map(|spec| {
            let arrow = if sort.arrow(spec.column).is_some() {
                ARROW_W
            } else {
                0
            };
            spec.label.chars().count() + arrow
        })
        .collect()
}

/// A table's column floors with the sorted column's raised to hold its label
/// and the arrow on one line. The name column at `flex` pays for the raise,
/// so the floors' sum — and with it every other column at every width — is
/// what it was: only the arrow's two cells move with the sort.
#[must_use]
pub fn arrow_floors<T: SortedTable>(
    sort: &TableSort<T>,
    declared: &[usize],
    flex: usize,
) -> Vec<usize> {
    let mut floors = declared.to_vec();
    let sorted = T::COLUMNS
        .iter()
        .position(|spec| spec.column == sort.column());
    if let Some(at) = sorted.filter(|at| *at != flex && *at < floors.len()) {
        let need = T::label(sort.column()).chars().count() + ARROW_W;
        let raise = need.saturating_sub(floors[at]);
        floors[at] += raise;
        floors[flex] = floors[flex].saturating_sub(raise).max(1);
    }
    floors
}
