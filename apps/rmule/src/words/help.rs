//! The help overlay's rows: a table of what every tab shares, one per tab, a
//! table each so a tab's key has one place to be said, and the words the
//! screens use without saying what they mean. The README keys section follows
//! these rows.

use crate::view::ViewId;

/// One row: its keys or its word, and what they do or mean.
pub type Binding = (&'static str, &'static str);

/// One table of the overlay, under its title.
#[derive(Clone, Copy, Debug)]
pub struct Section {
    /// The table's title.
    pub title: &'static str,
    /// Its rows.
    pub rows: &'static [Binding],
}

/// What every tab shares.
pub const EVERYWHERE: Section = Section {
    title: "Everywhere",
    rows: &[
        ("1–6", "switch view directly"),
        ("h / l  ← / →", "previous / next view"),
        ("j/k  ↑/↓", "select row in focused pane"),
        ("PgUp / PgDn", "a page; Ctrl-U / Ctrl-D too"),
        ("g / G", "top / bottom; Home / End too"),
        ("/", "filter the focused list as you type"),
        ("Space / T", "tag a row / every row on show"),
        (
            "Tab / Shift-Tab",
            "cycle panes (the focused pane's border stands out)",
        ),
        ("z", "zoom the focused pane to the whole tab, or back"),
        (
            "m / Enter",
            "row action menu; acts on the tagged rows if any",
        ),
        ("x", "take the row away, or the tagged rows; asks first"),
        ("s / S", "sort the focused table by next column / reverse"),
        (
            "?",
            "this help; type to filter it, ↑/↓ and PgUp/PgDn scroll",
        ),
        ("q", "quit; asks first while anything is under way"),
        ("Ctrl-C", "quit, from anywhere"),
        ("Ctrl-Z", "stop as a job; transfers stand still until fg"),
        ("Ctrl-L", "repaint the screen"),
        (
            "Esc",
            "clear a filter or the tags; close a menu, a form or a confirm; \
             leave the query; a share question waits for y or n",
        ),
        (
            "Ctrl-A / E",
            "in a text field: to the start / end; Alt-←/→ by word",
        ),
        (
            "Ctrl-U/K/W/Y",
            "in a text field: cut to start / to end / a word; put it back",
        ),
        ("Tab", "in a path field: complete it; ~ is your home"),
        (
            "mouse",
            "click tab/row selects, header sorts, a click runs a menu item, \
             the wheel scrolls the pane under it",
        ),
        (
            "copy text",
            "hold Shift, or Option on macOS, to drag; or turn Mouse off in \
             Settings or start with --no-mouse: clicks and the wheel then do nothing",
        ),
    ],
};

/// Networks.
pub const NETWORKS: Section = Section {
    title: "Networks",
    rows: &[
        ("a", "add server"),
        ("U", "update server list from URL"),
        (
            "c",
            "connect to the selected server, or disconnect from the one you are on",
        ),
        ("K", "start or stop Kad"),
        ("d", "the selected server's grants, flags and health"),
        (
            "f",
            "in the log: every line, warnings and failures, or failures",
        ),
    ],
};

/// Searches.
pub const SEARCHES: Section = Section {
    title: "Searches",
    rows: &[
        ("i", "focus query input; / too while no result is on show"),
        ("o", "type/size/sources/extension filters"),
        ("[ / ]", "previous / next held search"),
        ("x / n", "stop or close a search / server's next page"),
        ("u", "bring back the search closed last"),
    ],
};

/// Transfers.
pub const TRANSFERS: Section = Section {
    title: "Transfers",
    rows: &[
        (
            "p",
            "pause or resume the selected download, or the tagged ones",
        ),
        (
            "P",
            "pause every download on show; with none running, resume them",
        ),
        ("x", "cancel the selected download, or the tagged ones"),
        ("d", "the selected download's file details"),
        ("C", "clear all completed"),
        ("L", "add a download from a pasted eD2k link"),
        (
            "v",
            "preview the selected download in the player set in Settings",
        ),
    ],
};

/// Shared Files.
pub const SHARED: Section = Section {
    title: "Shared Files",
    rows: &[
        ("x", "unshare the selected file, or the tagged ones"),
        ("f", "uploads: active only, or every peer"),
        ("[ / ]", "filter by directory"),
    ],
};

/// Statistics.
pub const STATISTICS: Section = Section {
    title: "Statistics",
    rows: &[("w", "graph seconds, a minute a column, or an hour a column")],
};

/// Settings.
pub const SETTINGS: Section = Section {
    title: "Settings",
    rows: &[
        ("Enter  ←→  h/l", "edit a field / step a selector"),
        ("x", "stop sharing the selected directory"),
    ],
};

/// What the screens say without saying what it means.
pub const WORDS: Section = Section {
    title: "Words",
    rows: &[
        ("HighID", "peers can reach you directly"),
        ("LowID", "peers cannot reach you; the server relays for you"),
        (
            "Grants",
            "what a server lets a client do: its limits and flags",
        ),
        ("carried", "a file a scan kept its hash for, unread"),
        (
            "Stalled",
            "holds a slot and has moved no bytes for 30 seconds",
        ),
        (
            "Sources 42 (7)",
            "peers that have the file (of them, with all of it)",
        ),
        (
            "Requests 3 (12)",
            "this run (all time); Accepted, Transferred too",
        ),
        ("Done 42%", "bytes verified against the file's hashes"),
        ("▸  •", "the row the cursor is on; a tagged row"),
    ],
};

/// How a result's mark and the selection look in a theme with colour: each mark
/// has its colour, and all but `have` an attribute as well.
const MARKS: Section = Section {
    title: "Marks on a result",
    rows: &[
        ("downloading", "in Transfers now: its colour, bold"),
        (
            "failed",
            "its download failed and holds its place: its colour, bold, underlined",
        ),
        ("have", "on your disk, shared: its colour"),
        (
            "withheld",
            "rmule cannot read it now, offered to nobody: its colour, underlined",
        ),
        ("had", "downloaded once, no longer held: its colour, italic"),
        ("cancelled", "you cancelled it: its colour, struck through"),
        (
            "selected",
            "the focused pane's row is bold whatever its mark: its word says which",
        ),
    ],
};

/// [`MARKS`] with no colour: the attribute is all there is.
const MARKS_NO_COLOUR: Section = Section {
    title: "Marks on a result",
    rows: &[
        ("downloading", "in Transfers now: bold"),
        (
            "failed",
            "its download failed and holds its place: bold, underlined",
        ),
        ("have", "on your disk, shared: dim"),
        (
            "withheld",
            "rmule cannot read it now, offered to nobody: underlined",
        ),
        ("had", "downloaded once, no longer held: italic"),
        ("cancelled", "you cancelled it: struck through"),
        (
            "selected",
            "reversed and bold in the focused pane, underlined in another, \
             whatever its mark: its word says which",
        ),
    ],
};

/// The overlay's tables for a visit from `active`: that tab's first, then what
/// every tab shares, the rest in the tabs' order, and the words last, with what
/// a mark looks like in a theme with colour or, `colourless`, without.
#[must_use]
pub fn sections(active: ViewId, colourless: bool) -> Vec<Section> {
    let tabs = [
        (ViewId::Networks, NETWORKS),
        (ViewId::Searches, SEARCHES),
        (ViewId::Transfers, TRANSFERS),
        (ViewId::SharedFiles, SHARED),
        (ViewId::Statistics, STATISTICS),
        (ViewId::Settings, SETTINGS),
    ];
    let own = tabs.iter().filter(|(tab, _)| *tab == active);
    let rest = tabs.iter().filter(|(tab, _)| *tab != active);
    own.map(|(_, section)| *section)
        .chain([EVERYWHERE])
        .chain(rest.map(|(_, section)| *section))
        .chain([WORDS, if colourless { MARKS_NO_COLOUR } else { MARKS }])
        .collect()
}
