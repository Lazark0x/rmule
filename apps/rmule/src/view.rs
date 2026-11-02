//! The v1 views (spec §1). Chrome switches between them; each view's content
//! is its own component; Statistics returns from the §6 deferral registry
//! and Settings with it (the prefs-editing deferral, pulled in).

use crate::stored_keys;
use crate::words::labels;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
/// Which tab is up. The declaration order *is* the tab order — aMule's:
/// Networks, Searches, Transfers, Shared Files, Statistics, then Settings —
/// and the digit row, the `h`/`l` cycle and the tab bar all derive from it.
pub enum ViewId {
    /// The eD2k server list and the Kad panel; the view a first run opens on.
    #[default]
    Networks,
    /// Search entry and its result tables.
    Searches,
    /// Downloads and their sources.
    Transfers,
    /// What this node offers others.
    SharedFiles,
    /// Rate-history graphs + session totals (spec §6 return).
    Statistics,
    /// The preferences editor over the config store (spec §6 return).
    Settings,
}

impl ViewId {
    /// Every view in tab order — the one list the digit row, the cycle, and
    /// the tab bar are derived from.
    pub const ALL: [Self; 6] = [
        Self::Networks,
        Self::Searches,
        Self::Transfers,
        Self::SharedFiles,
        Self::Statistics,
        Self::Settings,
    ];

    /// How many views the digit row and the `h`/`l` cycle span. Derived from
    /// [`Self::ALL`] so a seventh view cannot desync the two.
    pub(crate) const COUNT: u8 = Self::ALL.len() as u8;

    /// The `1–6` direct-switch digit.
    #[must_use]
    pub const fn number(self) -> u8 {
        match self {
            Self::Networks => 1,
            Self::Searches => 2,
            Self::Transfers => 3,
            Self::SharedFiles => 4,
            Self::Statistics => 5,
            Self::Settings => 6,
        }
    }

    /// The label the tab bar prints.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Transfers => labels::TAB_TRANSFERS,
            Self::Searches => labels::TAB_SEARCHES,
            Self::Networks => labels::TAB_NETWORKS,
            Self::SharedFiles => labels::TAB_SHARED_FILES,
            Self::Statistics => labels::TAB_STATISTICS,
            Self::Settings => labels::TAB_SETTINGS,
        }
    }

    /// The label where six full ones do not fit: the two longest give up
    /// their second word or their tail, so every tab keeps a name.
    #[must_use]
    pub const fn short_title(self) -> &'static str {
        match self {
            Self::SharedFiles => labels::TAB_SHARED_SHORT,
            Self::Statistics => labels::TAB_STATISTICS_SHORT,
            other => other.title(),
        }
    }

    /// The word the tab is stored under. Stable: renaming one would forget an
    /// installed value.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::Networks => stored_keys::TAB_NETWORKS,
            Self::Searches => stored_keys::TAB_SEARCHES,
            Self::Transfers => stored_keys::TAB_TRANSFERS,
            Self::SharedFiles => stored_keys::TAB_SHARED,
            Self::Statistics => stored_keys::TAB_STATISTICS,
            Self::Settings => stored_keys::TAB_SETTINGS,
        }
    }

    /// Read a stored tab; anything unrecognised, or nothing, is the tab the
    /// app opens on by default.
    #[must_use]
    pub fn parse(key: Option<&str>) -> Self {
        Self::ALL
            .into_iter()
            .find(|view| Some(view.key()) == key)
            .unwrap_or_default()
    }

    /// Inverse of [`number`](Self::number); `None` for a digit no view claims.
    #[must_use]
    pub fn from_number(number: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|view| view.number() == number)
    }

    /// Tab-cycle neighbor (`l`), wrapping.
    #[must_use]
    pub fn next(self) -> Self {
        Self::from_number(self.number() % Self::COUNT + 1).unwrap_or(self)
    }

    /// Tab-cycle neighbor (`h`), wrapping.
    #[must_use]
    pub fn prev(self) -> Self {
        Self::from_number((self.number() + Self::COUNT - 2) % Self::COUNT + 1).unwrap_or(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cycling_wraps_both_directions_across_every_view() {
        assert_eq!(ViewId::Statistics.next(), ViewId::Settings);
        assert_eq!(ViewId::Settings.next(), ViewId::Networks);
        assert_eq!(ViewId::Networks.prev(), ViewId::Settings);
        for view in ViewId::ALL {
            assert_eq!(view.next().prev(), view);
        }
    }

    #[test]
    fn the_digit_row_covers_every_view_exactly_once() {
        let numbers: Vec<u8> = ViewId::ALL.iter().map(|view| view.number()).collect();
        assert_eq!(numbers, (1..=ViewId::COUNT).collect::<Vec<_>>());
        assert_eq!(ViewId::from_number(6), Some(ViewId::Settings));
        assert_eq!(ViewId::from_number(7), None);
    }
}
