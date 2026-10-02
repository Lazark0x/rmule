//! The selection bound to a row's identity rather than its position.
//!
//! Rows re-order live — a search batch replaces the whole set, a sort change
//! reshuffles it — and an index cursor would slide another row under an Enter
//! already on its way. So the cursor remembers *which* row: until the operator
//! moves it, it rests on the first row whatever that is; once moved, it follows
//! its row; if its row leaves the set, it stays at the same height and binds to
//! whichever row now stands there.

use ratatui::crossterm::event::KeyCode;

/// A move of the cursor the keys ask for: the one vocabulary every table reads
/// its row-moving keys in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowMove {
    /// `j` / `↓` (`1`) and `k` / `↑` (`-1`): one row, stopping at the ends.
    Step(isize),
    /// `g`: the first row.
    First,
    /// `G`: the last row.
    Last,
}

impl RowMove {
    /// The move `code` asks for, if it asks for one. The wheel arrives as `↑` /
    /// `↓`, so it is covered here too.
    #[must_use]
    pub fn of(code: KeyCode) -> Option<Self> {
        match code {
            KeyCode::Char('j') | KeyCode::Down => Some(Self::Step(1)),
            KeyCode::Char('k') | KeyCode::Up => Some(Self::Step(-1)),
            KeyCode::Char('g') => Some(Self::First),
            KeyCode::Char('G') => Some(Self::Last),
            _ => None,
        }
    }
}

/// Where the selection is, by row identity.
#[derive(Clone, Debug)]
pub struct RowCursor<I> {
    /// `None` until the operator moves the cursor: it rests on the first row.
    bound: Option<I>,
    /// Where the bound row last stood, for when it leaves the set.
    index: usize,
}

impl<I> Default for RowCursor<I> {
    fn default() -> Self {
        Self {
            bound: None,
            index: 0,
        }
    }
}

impl<I: Eq + Clone> RowCursor<I> {
    /// The selected row's position in `ids` (the rows' identities in display
    /// order), or `None` for an empty table.
    pub fn place(&mut self, ids: &[I]) -> Option<usize> {
        let last = ids.len().checked_sub(1)?;
        if let Some(bound) = &self.bound {
            self.index = match ids.iter().position(|id| id == bound) {
                Some(index) => index,
                None => {
                    let index = self.index.min(last);
                    self.bound = Some(ids[index].clone());
                    index
                }
            };
            Some(self.index)
        } else {
            Some(0)
        }
    }

    /// The operator put the cursor on `index`: bind to that row. Clamped into
    /// the table; nothing happens on an empty one.
    pub fn select(&mut self, ids: &[I], index: usize) {
        let Some(last) = ids.len().checked_sub(1) else {
            return;
        };
        self.index = index.min(last);
        self.bound = Some(ids[self.index].clone());
    }

    /// Move the cursor `delta` rows from where it is (`j`/`k`), clamped.
    pub fn step(&mut self, ids: &[I], delta: isize) {
        if let Some(at) = self.place(ids) {
            self.select(ids, at.saturating_add_signed(delta));
        }
    }

    /// Carry out a [`RowMove`] over `ids`.
    pub fn apply(&mut self, ids: &[I], movement: RowMove) {
        match movement {
            RowMove::Step(delta) => self.step(ids, delta),
            RowMove::First => self.select(ids, 0),
            RowMove::Last => self.select(ids, usize::MAX),
        }
    }

    /// The selected row's identity, binding the resting cursor to the first
    /// row — for an action that must name the row it was aimed at even if a
    /// batch lands before it runs.
    pub fn pin(&mut self, ids: &[I]) -> Option<I> {
        let at = self.place(ids)?;
        self.select(ids, at);
        self.bound.clone()
    }

    /// Back to resting on the first row (a fresh set: a new search).
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}
