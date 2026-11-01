//! **Tags**: the rows of a table an action takes together. `Space` tags the
//! row under the cursor and steps on, `T` tags every row on show or, with all
//! of them tagged, none, and `Esc` lets them all go. With a tag standing,
//! `p`, `x` and the row menu act on the tagged rows, else on the row under the
//! cursor: every table asks [`Tags::targets`].

use std::collections::BTreeSet;

use ratatui::crossterm::event::KeyCode;

use crate::table_sort::RowCursor;
use crate::views::ViewOutcome;

/// One table's tagged rows, by identity.
#[derive(Clone, Debug)]
pub(crate) struct Tags<I> {
    tagged: BTreeSet<I>,
}

impl<I> Default for Tags<I> {
    fn default() -> Self {
        Self {
            tagged: BTreeSet::new(),
        }
    }
}

impl<I: Ord + Clone> Tags<I> {
    /// Offer a key: `ids` are the rows on show, in order.
    pub(crate) fn key(
        &mut self,
        code: KeyCode,
        ids: &[I],
        cursor: &mut RowCursor<I>,
    ) -> Option<ViewOutcome> {
        match code {
            KeyCode::Char(' ') => {
                let id = cursor.pin(ids)?;
                if !self.tagged.remove(&id) {
                    self.tagged.insert(id);
                }
                cursor.step(ids, 1);
            }
            KeyCode::Char('T') if !ids.is_empty() => {
                if ids.iter().all(|id| self.tagged.contains(id)) {
                    self.tagged.clear();
                } else {
                    self.tagged.extend(ids.iter().cloned());
                }
            }
            KeyCode::Esc if !self.tagged.is_empty() => self.tagged.clear(),
            _ => return None,
        }
        Some(ViewOutcome::Redraw)
    }

    /// Whether `id` is tagged.
    #[must_use]
    pub(crate) fn contains(&self, id: &I) -> bool {
        self.tagged.contains(id)
    }

    /// How many are tagged.
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.tagged.len()
    }

    /// Whether any stands.
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.tagged.is_empty()
    }

    /// Let go of every row `live` no longer finds.
    pub(crate) fn keep(&mut self, live: impl Fn(&I) -> bool) {
        self.tagged.retain(live);
    }

    /// Let them all go.
    pub(crate) fn clear(&mut self) {
        self.tagged.clear();
    }

    /// What an action takes: the tagged rows, else the row under the cursor.
    #[must_use]
    pub(crate) fn targets(&self, under_cursor: Option<I>) -> Vec<I> {
        if self.tagged.is_empty() {
            under_cursor.into_iter().collect()
        } else {
            self.tagged.iter().cloned().collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn space_tags_and_steps_on_and_the_tagged_rows_are_the_targets() {
        let ids = [1u8, 2, 3];
        let mut cursor = RowCursor::default();
        let mut tags = Tags::default();
        assert_eq!(tags.targets(Some(2)), [2], "no tag: the row under the cursor");
        tags.key(KeyCode::Char(' '), &ids, &mut cursor);
        tags.key(KeyCode::Char(' '), &ids, &mut cursor);
        assert_eq!(cursor.place(&ids), Some(2));
        assert_eq!(tags.targets(Some(3)), [1, 2]);
        cursor.step(&ids, -1);
        tags.key(KeyCode::Char(' '), &ids, &mut cursor);
        assert_eq!(tags.targets(None), [1], "a second Space lets it go");
    }

    #[test]
    fn t_takes_every_row_on_show_then_none_and_esc_lets_all_go() {
        let ids = [1u8, 2];
        let mut cursor = RowCursor::default();
        let mut tags = Tags::default();
        tags.key(KeyCode::Char('T'), &ids, &mut cursor);
        assert_eq!(tags.len(), 2);
        tags.key(KeyCode::Char('T'), &ids, &mut cursor);
        assert!(tags.is_empty());
        tags.key(KeyCode::Char('T'), &ids, &mut cursor);
        assert!(tags.key(KeyCode::Esc, &ids, &mut cursor).is_some());
        assert!(tags.is_empty());
        assert!(tags.key(KeyCode::Esc, &ids, &mut cursor).is_none());
    }
}
