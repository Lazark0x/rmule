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
    /// (`"true"`/`"false"`, off when unset — ADR-0095, "Connecting is the
    /// operator's act"; aMule's `Autoconnect`, which rmule keeps off by
    /// default).
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
        }
    }
}
