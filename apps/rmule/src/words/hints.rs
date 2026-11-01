//! The key hints on a pane's border and under a form: a key and what it does.
//! Every hint reads the one way, and a key is never part of a word: a language
//! words what the key does and leaves the key as it is.

/// One key and what it does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hint {
    /// The key.
    pub key: &'static str,
    /// What it does here.
    pub does: &'static str,
}

impl Hint {
    const fn new(key: &'static str, does: &'static str) -> Self {
        Self { key, does }
    }

    /// The same key, doing something the caller worded.
    #[must_use]
    pub const fn doing(self, does: &'static str) -> Self {
        Self::new(self.key, does)
    }
}

/// What stands between two hints, and what a pane's border gives way at.
pub const GAP: &str = "  ";

/// A hint line for a border: padded, its keys separated by [`GAP`].
#[must_use]
pub fn line(hints: &[Hint]) -> String {
    if hints.is_empty() {
        return String::new();
    }
    let keys: Vec<String> = hints
        .iter()
        .map(|hint| format!("{} {}", hint.key, hint.does))
        .collect();
    format!(" {} ", keys.join(GAP))
}

/// Pause or resume a download.
pub const PAUSE: Hint = Hint::new("p", "pause");
/// Open the row menu.
pub const MENU: Hint = Hint::new("m", "menu");
/// Open the row menu, where the pane leads with it.
pub const ENTER_MENU: Hint = Hint::new("Enter", "menu");
/// Filter the list.
pub const FILTER: Hint = Hint::new("/", "filter");
/// Add a download.
pub const ADD_LINK: Hint = Hint::new("L", "add");
/// Move to the sources pane.
pub const TO_SOURCES: Hint = Hint::new("Tab", "sources");
/// Move to the downloads pane.
pub const TO_DOWNLOADS: Hint = Hint::new("Tab", "downloads");
/// Move to the uploads pane.
pub const TO_UPLOADS: Hint = Hint::new("Tab", "uploads");
/// Move to the files pane.
pub const TO_FILES: Hint = Hint::new("Tab", "files");
/// Move to the log.
pub const TO_LOG: Hint = Hint::new("Tab", "log");
/// Tag the row.
pub const TAG: Hint = Hint::new("Space", "tag");
/// Clear what completed.
pub const CLEAR: Hint = Hint::new("C", "clear");
/// Walk the sort.
pub const SORT: Hint = Hint::new("s", "sort");
/// Reverse the sort.
pub const REVERSE: Hint = Hint::new("S", "reverse");
/// Zoom the pane.
pub const ZOOM: Hint = Hint::new("z", "zoom");
/// Show every peer.
pub const ALL_PEERS: Hint = Hint::new("f", "all");
/// Show the active peers.
pub const ACTIVE_PEERS: Hint = Hint::new("f", "active");
/// Move to the next field of a form.
pub const NEXT_FIELD: Hint = Hint::new("Tab", "field");
/// Step the type selector.
pub const STEP_TYPE: Hint = Hint::new("←→", "type");
/// Send the search.
pub const SEARCH: Hint = Hint::new("Enter", "search");
/// Close what is open.
pub const ESC_CLOSE: Hint = Hint::new("Esc", "close");
/// Give the keys back.
pub const ESC_LEAVE: Hint = Hint::new("Esc", "leave");
/// Drop what is typed.
pub const ESC_CANCEL: Hint = Hint::new("Esc", "cancel");
/// Focus the query.
pub const FOCUS_QUERY: Hint = Hint::new("i", "focus");
/// Open the filters.
pub const OPTIONS: Hint = Hint::new("o", "options");
/// Edit the filters.
pub const EDIT_FILTERS: Hint = Hint::new("o", "edit");
/// Walk the held searches.
pub const WALK_SEARCHES: Hint = Hint::new("[ ]", "search");
/// Stop a running search.
pub const STOP_SEARCH: Hint = Hint::new("x", "stop");
/// Close a held search.
pub const CLOSE_SEARCH: Hint = Hint::new("x", "close");
/// Ask the server for more.
pub const MORE: Hint = Hint::new("n", "more");
/// Bring back the search closed last.
pub const REOPEN: Hint = Hint::new("u", "reopen");
/// Connect to the selected server.
pub const CONNECT: Hint = Hint::new("c", "connect");
/// Disconnect from it.
pub const DISCONNECT: Hint = Hint::new("c", "disconnect");
/// End a dial.
pub const STOP_CONNECTING: Hint = Hint::new("c", "stop connecting");
/// End the re-making of a lost session.
pub const STOP_RECONNECTING: Hint = Hint::new("c", "stop reconnecting");
/// Add a server.
pub const ADD_SERVER: Hint = Hint::new("a", "add");
/// Update the server list.
pub const UPDATE_LIST: Hint = Hint::new("U", "update");
/// Show the details of a row.
pub const DETAILS: Hint = Hint::new("d", "details");
/// Complete a path.
pub const COMPLETE: Hint = Hint::new("Tab", "complete");
/// Keep what is typed.
pub const SAVE: Hint = Hint::new("Enter", "save");
/// Stop sharing a directory.
pub const STOP_SHARING: Hint = Hint::new("x", "stop sharing");
/// Move between rows.
pub const ROWS: Hint = Hint::new("j/k", "row");
/// Open the field.
pub const EDIT: Hint = Hint::new("Enter", "edit");
/// Step a selector.
pub const STEP: Hint = Hint::new("←→", "step");
/// Commit a form, worded by what the form does.
pub const COMMIT: Hint = Hint::new("Enter", "add");
