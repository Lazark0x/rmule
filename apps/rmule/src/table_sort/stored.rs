//! Every table's sort as the one `table_sorts` preference holds it:
//! `search=size:desc;transfers=name:asc`.
//!
//! One value for all tables, keyed by table inside it, so a table that gains a
//! sort writes an entry rather than needing a new store key. Entries for tables
//! this build does not know are kept verbatim — a newer build's sort survives
//! an older one's rewrite — and a malformed entry is skipped rather than
//! failing the whole preference: a table then shows its default.

use std::collections::BTreeMap;

use super::Direction;

/// The stored sorts, table by table.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TableSorts(BTreeMap<String, (String, Direction)>);

impl TableSorts {
    /// Read the preference's text; `None` (never written) is no entries.
    #[must_use]
    pub fn parse(text: Option<&str>) -> Self {
        let entries = text
            .unwrap_or_default()
            .split(';')
            .filter_map(|entry| {
                let (table, sort) = entry.split_once('=')?;
                let (column, direction) = sort.split_once(':')?;
                let direction = match direction {
                    "asc" => Direction::Ascending,
                    "desc" => Direction::Descending,
                    _ => return None,
                };
                (!table.is_empty() && !column.is_empty())
                    .then(|| (table.to_string(), (column.to_string(), direction)))
            })
            .collect();
        Self(entries)
    }

    /// The preference's text.
    #[must_use]
    pub fn text(&self) -> String {
        self.0
            .iter()
            .map(|(table, (column, direction))| {
                let direction = match direction {
                    Direction::Ascending => "asc",
                    Direction::Descending => "desc",
                };
                format!("{table}={column}:{direction}")
            })
            .collect::<Vec<_>>()
            .join(";")
    }

    /// `table`'s stored column key and direction.
    #[must_use]
    pub fn get(&self, table: &str) -> Option<(&str, Direction)> {
        self.0
            .get(table)
            .map(|(column, direction)| (column.as_str(), *direction))
    }

    /// Record `table`'s sort, replacing what it had.
    pub fn set(&mut self, table: &str, column: &str, direction: Direction) {
        self.0
            .insert(table.to_string(), (column.to_string(), direction));
    }
}
