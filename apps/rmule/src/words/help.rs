//! The help overlay's rows: one table of bindings for what every tab shares and
//! one per tab, a table each so a tab's key has one place to be said. The README
//! keys section follows these rows.

/// One binding: its keys, and what they do.
pub type Binding = (&'static str, &'static str);

/// What every tab shares.
pub const EVERYWHERE: &[Binding] = &[
    ("1–6", "switch view directly"),
    ("h / l", "previous / next view"),
    ("j/k  ↑/↓", "select row in focused pane"),
    ("g / G", "top / bottom"),
    ("Tab / Shift-Tab", "cycle panes (accent border = focus)"),
    ("m / Enter", "row action menu"),
    ("s / S", "sort the focused table by next column / reverse"),
    ("?", "this help; j/k, PgUp/PgDn scroll it when it is long"),
    ("q", "quit; asks first while a download runs"),
    ("Ctrl-C", "quit, from anywhere"),
    ("Esc", "close a menu, a form or a question; leave the query"),
    (
        "mouse",
        "click tab/row selects, header sorts, wheel scrolls",
    ),
];

/// Networks.
pub const NETWORKS: &[Binding] = &[
    ("a", "Networks: add server"),
    ("U", "Networks: update server list from URL"),
    (
        "c",
        "Networks: connect to the selected server, or disconnect from the one you are on",
    ),
    ("K", "Networks: start or stop Kad"),
];

/// Searches.
pub const SEARCHES: &[Binding] = &[
    ("/", "Searches: focus query input"),
    ("o", "Searches: type/size/sources/extension filters"),
    ("[ / ]", "Searches: previous / next held search"),
    (
        "x / n",
        "Searches: stop or close a search / server's next page",
    ),
];

/// Transfers.
pub const TRANSFERS: &[Binding] = &[
    ("p", "Transfers: pause or resume the selected download"),
    ("C", "Transfers: clear all completed"),
    ("L", "Transfers: add a download from a pasted eD2k link"),
    (
        "v",
        "Transfers: preview the selected download in the player set in Settings",
    ),
];

/// Shared Files.
pub const SHARED: &[Binding] = &[
    ("a", "Shared: active files only, or every file"),
    ("[ / ]", "Shared: filter by directory"),
];

/// Settings.
pub const SETTINGS: &[Binding] = &[
    ("Enter  ← / →", "Settings: edit a field / step a selector"),
    ("x", "Settings: stop sharing the selected directory"),
];

/// Every table, in the tabs' order.
pub const TABLES: [&[Binding]; 6] = [EVERYWHERE, NETWORKS, SEARCHES, TRANSFERS, SHARED, SETTINGS];
