//! The v1 views (spec §1). Chrome switches between them; each view's content
//! is its own component; Statistics returns from the §6 deferral registry
//! and Settings with it (the prefs-editing deferral, pulled in).

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
/// Which tab is up. The declaration order *is* the tab order — aMule's:
/// Networks, Searches, Transfers, Shared Files, Statistics, then Settings —
/// and the digit row, the `h`/`l` cycle and the tab bar all derive from it.
pub enum ViewId {
    /// The eD2k server list and the Kad panel; the view the app opens on.
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
            Self::Transfers => "Transfers",
            Self::Searches => "Searches",
            Self::Networks => "Networks",
            Self::SharedFiles => "Shared Files",
            Self::Statistics => "Statistics",
            Self::Settings => "Settings",
        }
    }

    /// Inverse of [`number`](Self::number); `None` for a digit no view claims.
    #[must_use]
    pub fn from_number(number: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|view| view.number() == number)
    }

    /// Tab-cycle neighbor (`l`), wrapping.
    #[must_use]
    pub fn next(self) -> Self {
        Self::from_number(self.number() % Self::COUNT + 1).expect("cycle stays in range")
    }

    /// Tab-cycle neighbor (`h`), wrapping.
    #[must_use]
    pub fn prev(self) -> Self {
        Self::from_number((self.number() + Self::COUNT - 2) % Self::COUNT + 1)
            .expect("cycle stays in range")
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
