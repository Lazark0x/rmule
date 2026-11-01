//! The keys this app keeps for itself in the one preferences table (ADR-0069):
//! core stores them under these names, beside its own keys, and never
//! interprets them. Each value is parsed here, where its one consumer lives.

/// One of this app's own preferences.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrontEndKey {
    /// The terminal theme the app starts in (`dark`/`light`/`256`, or unset
    /// for environment detection).
    Theme,
    /// Every table's **Table Sort** (ADR-0070), one entry per table in a
    /// single value, so a table that gains a sort adds an entry rather than a
    /// key.
    TableSorts,
    /// Whether the app performs the operator's connect at attach
    /// (`"true"`/`"false"`, on when unset, so a stored `"false"` is the
    /// operator's off and stays — ADR-0095, "Connecting is the operator's
    /// act"; aMule's `Autoconnect`).
    ConnectAtStart,
    /// The server the operator last connected to, as `host:port`: what a
    /// connect at start dials. Written on every `Connected`.
    LastServer,
    /// Whether the Run Log is written at its full level (`"true"`/`"false"`,
    /// off when unset): lean holds reachability evidence only, full adds peer
    /// addresses, file names, paths and hashes. Shared with every front end
    /// that writes the Run Log, under core's
    /// [`PREFERENCE_KEY`](rmule_core::run_log::PREFERENCE_KEY).
    RunLogFull,
    /// The **Player Command** (ADR-0114): the operator's player as text,
    /// split into words at each Preview launch; unset when absent or empty,
    /// and Preview is then off.
    PlayerCommand,
    /// The tab the app last showed, as [`ViewId::key`](crate::view::ViewId::key):
    /// what the next run opens on.
    LastTab,
    /// Whether the app writes rates and the tally to the terminal's title
    /// (`"true"`/`"false"`, off when unset).
    TerminalTitle,
    /// Whether a finished download rings the terminal's bell
    /// (`"true"`/`"false"`, off when unset).
    CompletionBell,
    /// Whether the app takes the mouse from the terminal.
    Mouse,
}

impl FrontEndKey {
    /// The `preferences.key` this entry is stored under. Stable: renaming one
    /// would orphan an installed value.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::Theme => "theme",
            Self::TableSorts => "table_sorts",
            Self::ConnectAtStart => "connect_at_start",
            Self::LastServer => "last_server",
            Self::RunLogFull => rmule_core::run_log::PREFERENCE_KEY,
            Self::PlayerCommand => "player_command",
            Self::LastTab => "last_tab",
            Self::TerminalTitle => "terminal_title",
            Self::CompletionBell => "completion_bell",
            Self::Mouse => "mouse",
        }
    }
}
