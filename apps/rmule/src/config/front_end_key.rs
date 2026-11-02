//! The keys this app keeps for itself in the one preferences table (ADR-0069):
//! core stores them under these names, beside its own keys, and never
//! interprets them. A key that is on or off is one row of [`AppFlag`]'s table;
//! the rest are named in [`FrontEndKey`], each value parsed where its one
//! consumer lives.

rmule_core::flag_table! {
    /// A **Flag** this app keeps for itself: one row is the whole of a new
    /// on/off preference but for its words
    /// ([`app_flag_words`](crate::words::settings::app_flag_words)) and its
    /// place in the Settings form.
    pub enum AppFlag {
        /// Whether the app performs the operator's connect at attach, to the
        /// server it last connected to (ADR-0095, "Connecting is the
        /// operator's act"; aMule's `Autoconnect`). With no server yet there
        /// is nothing to connect to.
        ConnectAtStart = "connect_at_start", on: true;
        /// Whether the Run Log is written at its full level: lean holds
        /// reachability evidence only, full adds peer addresses, file names,
        /// paths and hashes. Shared with every front end that writes the Run
        /// Log, under core's
        /// [`PREFERENCE_KEY`](rmule_core::run_log::PREFERENCE_KEY).
        RunLogFull = rmule_core::run_log::PREFERENCE_KEY, on: false;
        /// Whether the app writes rates and the tally to the terminal's
        /// title: a title is the operator's until they give it up.
        TerminalTitle = "terminal_title", on: false;
        /// **Reader Mode**: the terminal's cursor rests on the selected row
        /// and the data tick repaints nothing on its own.
        ReaderMode = "reader_mode", on: false;
        /// Whether a finished download rings the terminal's bell.
        CompletionBell = "completion_bell", on: false;
        /// Whether the app takes the mouse from the terminal; off, a drag
        /// selects text as in any terminal, and clicks and the wheel do
        /// nothing.
        Mouse = "mouse", on: true;
    }
}

impl AppFlag {
    /// When a saved flag takes effect: at once, but for connect at start,
    /// which only a start reads.
    #[must_use]
    pub const fn takes_effect(self) -> rmule_core::TakesEffect {
        if matches!(self, Self::ConnectAtStart) {
            rmule_core::TakesEffect::NextStart
        } else {
            rmule_core::TakesEffect::Now
        }
    }
}

/// One of this app's own preferences that is more than on or off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrontEndKey {
    /// The terminal theme the app starts in (`dark`/`light`/`256`, or unset
    /// for environment detection).
    Theme,
    /// Every table's **Table Sort** (ADR-0070), one entry per table in a
    /// single value, so a table that gains a sort adds an entry rather than a
    /// key.
    TableSorts,
    /// The server the operator last connected to, as `host:port`: what a
    /// connect at start dials. Written on every `Connected`.
    LastServer,
    /// The **Player Command** (ADR-0114): the operator's player as text,
    /// split into words at each Preview launch; unset when absent or empty,
    /// and Preview is then off.
    PlayerCommand,
    /// The tab the app last showed, as [`ViewId::key`](crate::view::ViewId::key):
    /// what the next run opens on.
    LastTab,
}

impl FrontEndKey {
    /// The `preferences.key` this entry is stored under. Stable: renaming one
    /// would orphan an installed value.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::Theme => "theme",
            Self::TableSorts => "table_sorts",
            Self::LastServer => "last_server",
            Self::PlayerCommand => "player_command",
            Self::LastTab => "last_tab",
        }
    }
}
