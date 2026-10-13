# rmule

`rmule` is the terminal front-end (ADR-0069): a pure UI state spine folded from core events, a chrome shell, and six views that render it — all of it testable without a terminal, tokio, or a live core.

## Language

**Edge**:
A lifecycle fact core reports once, as it happens — a download was queued, a server answered, a search completed. Edges fold into [`UiState`] the instant they arrive, because nothing else will ever report them again. The fold is pure and returns only a render dirty hint.
_Avoid_: event (too broad — a level arrives as an event too), update, notification

**Level**:
A byte-count fact core republishes *whole* on every data tick — the diagnostics snapshot and the rates synthesized from it. Levels land latest-state-wins and are never merged, so the UI cannot accumulate a number core never observed. A view joins levels to its rows by id at render time rather than caching them.
_Avoid_: state, metrics, counters (core's counters are the source; a level is the snapshot of them)

**Data tick**:
The bridge's 1 Hz poll: read `diagnostics_snapshot()`, synthesize transfer rates, patch in the Kad facts the sync accessor cannot see, and publish the result as one snapshot action. The only clock the UI core has — every time-bearing fact is stamped with the tick's injected instant, never a wall clock read at render.
_Avoid_: refresh, frame, poll loop (the render loop is separate and runs at its own pace)

**View state**:
What a view owns: selection, scroll offset, focus, which modal is up, what has been typed into it. Never data — a view that held a copy of a download row could show a row core does not have. The split is what lets every view test as a pure function of `(UiState, view state, now)`.
_Avoid_: model, local state, component state

**Honest degrade**:
Rendering a fact core does not surface as a visible absence — a dash, or a control greyed *with its reason* — rather than a zero, an invented name, or a hidden control. A ping nobody measured reads `—`; an action that would be rejected says why it is unavailable. The columns and controls stay because the spec pins the set; the dash is the honest state until core carries the fact.
_Avoid_: placeholder, empty state, fallback value (a fallback invents; a degrade admits)

**No dead UI**:
The rule honest degrades serve: every control the chrome offers does something, and every fact it shows was observed. A control that cannot work is greyed with its reason, not silently inert.
_Avoid_: disabled control (that is the mechanism, not the rule), stub

**Glyph golden**:
A render snapshot compared glyph-exactly against `tests/goldens/<name>.txt`, drawn through ratatui's `TestBackend` at a fixed size with trailing whitespace trimmed. Goldens are recorded evidence of what the view draws: they are re-blessed deliberately (`UPDATE_GOLDENS=1`), never as a way to make a failing test pass.
_Avoid_: snapshot test (too generic), screenshot, visual test

**Chrome**:
Everything around the views: the tab bar, the status bar and its width budget, the help overlay, and the flash. It owns no core data — it reads the same `UiState` the views do.
_Avoid_: layout, shell, frame — as names for the chrome. `Frame` stays ratatui's word for the surface being drawn into, so `draw_frame(frame: &mut Frame, …)` reads right.

**Tab**:
One of the six top-level surfaces the chrome switches between, named by `ViewId` and drawn in the tab bar. A tab is what the operator selects — a digit, `h`/`l`, or a click; the **view** is the component that draws it, and exactly one is active at a time. What the chrome hands that view is a content rect, never the whole frame.
_Avoid_: page, screen, window

**Pane**:
A bounded region *inside* one view's content rect: the server table, the log and the Kad panel in Networks; the files and upload-peers halves of Shared Files. Focus inside a view lives at pane granularity — the focused pane takes the navigation keys, everything else bubbles to the globals. A view caches each pane's rect at draw time, so a click is hit-tested against the layout that was actually drawn rather than one recomputed from a stale width. A pane's title and its key hint share its top border and give way whole when it is narrow — the hint's keys first, last first, then the title's clauses, last first — never cut mid-word.
_Avoid_: section, widget, subview

**Flash**:
A transient one-line message the app loop shows and expires — how a view reports something it could not do. Distinct from the status bar's info feed, which carries the last notable *core* fact and is folded into `UiState`. One caller is not a view: `App::graceful_quit` fires it directly and event-driven, never on a timer — the opening "Shutting down…" before any step starts, then one redraw per `CoreEvent::Quitting { step }` action naming the step actually running, and, if the bridge's `CORE_SHUTDOWN_GRACE` elapses before the core's flush confirms, one more naming that.
_Avoid_: toast, alert, error message

**View outcome**:
What a view did with an input it was offered: ignored it (bubble on to the global bindings), redrew, or emitted an action. The one shape every view returns, so the app loop's dispatch is the same for all six.
_Avoid_: event result, handled flag

**Sentence**:
What the Networks log, the status bar's note and a flash hold: a line written from a code in a words module — `rmule-words`, whose glossary owns the term, or the TUI's own (`crate::words`, which re-exports the shared modules under the same names and adds the sentences that word the TUI's own types: its command line, a run with no core, a Settings edit, a server-health edge, a search entry's paging, the share set's tally, a preview's reasons and notes). `scripts/guards.sh` refuses a sentence made, or a Debug format, anywhere else in the TUI's source outside tests and `tracing` calls, and a glyph golden refuses to render `Some(`, `None`, a struct's braces, a Rust path or a byte array.
_Avoid_: message, string, label (a label is a word in a cell; a sentence is a line said)

**Off-screen line**:
The one line at the bottom of a table that says the selected row's values in the columns that gave way, as `Label value`, above the border's note naming those columns — every table the same way (`views::off_screen`), so a column giving way never loses its value. Shared Files' counters shortened to fit ride it too.
_Avoid_: detail row, tooltip, footer

**Greedy width**:
A column budget where each column declares a floor and the greedy column — the one holding free text; Servers has two — takes the slack left after the bounded columns (an endpoint, a phase, a rate) have asked for the widest value they show, up to a cap. A row that still cannot fit wraps onto further lines — every character is kept, and a line maps back to the row it came from, so nothing is ever cut. A header is never split: no column is narrower than its header and the sort arrow, and a pane too narrow for every header takes columns away in the table's stated give-way order — the greedy column last of all, never — and says on its bottom border which, or how many, are not shown.
_Avoid_: truncation, ellipsis, fixed layout

**Data directory**:
What the app resolves before anything else, by core's rule (`--data-dir`, `RMULE_DATA`, then `$XDG_DATA_HOME` or `$HOME` on Unix and `%LOCALAPPDATA%` on Windows): rmule's Durable Store (`rmule.redb`, ADR-0083) and the data files beside it (`clients.met`, `nodes.dat`, the IP filter). The TUI opens that one store and hands its seams to the embedded core, so a directory carries exactly one running client — the engine holds the file lock.
_Avoid_: profile, workspace, config dir (the config is a seam of the store, not a file of its own)

**Table Sort**:
The one column a table is ordered by, and its direction — view state, never core's. Every visible column can hold it and nothing else can; the header of the column holding it carries the arrow. Each table has one, kept across runs. Rows re-order as they change, and the cursor stays on its row rather than its position. A column may rank its rows into groups before its value (Transfers' Progress: moving bytes, then completed, then the rest); reversing reverses the value inside each group, never the groups. A table lists each column once — its stored key, header text and kind — so none of the three is a switch of its own.
_Avoid_: ordering, ranking, sort mode, sort key (a key with no column)

**Row Selection**:
What selecting a row is in every table: the cursor on a row's identity (`RowCursor`), moved by `j`/`k`/arrows and `g`/`G`, and the one mark it wears — the `▸` gutter marker and the selection background across the row, bold in the focused pane and dimmed, never hidden, in a pane without the focus. A click selects and focuses; `Enter`/`m` open the menu on the selected row. Settings' form fields are not rows.
_Avoid_: highlight, cursor row, active row, current row

**Viewport**:
What part of a scrollable list is on screen — its first item, how many items the last draw showed whole, and of how many — owned beside the **Row Selection** (`row_selection::viewport`), written by the draw, and the one source of the list's scroll bar and count. In a list with a cursor it follows the cursor, moving no further than keeps it on screen; in one without (the log, the help, the file details modal) it stays where it was scrolled, and one resting on its end keeps the end in view. While the list overflows, the bar (`▲` `█` `║` `▼`, the thumb's edges in eighths of a cell) takes the inner right column; the bottom border's right end says the cursor's row over the rows — or, while it overflows, the last item on screen over the total — and that count gives way last.
_Avoid_: scroll offset (one fact of it), scroll state, window, page

**Natural Direction**:
The direction a column takes when it first receives the **Table Sort**: ascending for text and for ranks (a word standing for an order: a type, a status, a priority), descending for quantities.
_Avoid_: default direction, initial order

**Tie Chain**:
What orders two rows the sort column holds equal: name ascending, then the row's identity. It makes every order total, and reversing the **Table Sort** never reverses it.
_Avoid_: secondary sort, stable sort, sort history

**Known-File Mark**:
What a search result says about the operator's own history with its file: **Downloading**, **Failed**, **Have**, **Withheld**, **Had** or **Cancelled**, at most one, in that precedence; no mark means the file is new to them. Drawn as the row's colour and a text attribute, in place of the source-count tint.
_Avoid_: file status, known flag, File-Known Predicate (core's serving gate, a different question)

**Held Search**:
One search the Search tab is keeping: its query, its status, its live **Search Result Set** and its own cursor. Its status line names each leg of the search in the TUI's words — server, other servers, Kad: waiting for a connection, waiting for Kad, searching, done, not asked / not running, not answered, and not sent with its reason — no server, no Kad contact answered, another Kad lookup holds the word, no word of three letters; a completed search names any leg that ended so beside its count. Any number are held side by side, each an entry on the strip under the query input; one not in view keeps receiving results. It lasts until the operator closes it or the run ends — nothing of it is written to disk.
_Avoid_: search tab (the Search tab holds them), search history, saved search, session


**Autoconnect**:
The Settings preference, off by default, under which the app sends at start the same `ConnectToServer` the `c` key sends, to the server last connected to (recorded on every `Connected` edge) — once, to that server alone (ADR-0095, "Connecting is the operator's act"). Nothing else in the app dials a server; with it off, a start connects to nothing and the Kad join waits for the operator's connect.
A session lost later is a different matter: core re-makes it while the operator's intent stands (**Server Intent**) — Autoconnect is only what dials at start.
_Avoid_: auto-reconnect (that is the Server Intent, not this preference), connect on startup to any server (aMule walks the list; rmule does not)

**Preview**:
The Transfers action — the row menu's item and the `v` key — that hands a **Preview Ready** download's **Download File Path** to the **Player Command**, or with none set to the **Default App**, as one argument, through no shell, on the player lane (ADR-0114). The menu greys it with the reason on a row it cannot act on, and a launch that cannot start flashes that reason.
_Avoid_: play, open, preview window

**Preview Ready**:
A Transfers row the Preview action acts on (ADR-0114): core says the download is **Previewable** (`DownloadMetadata::is_previewable()`, read, never re-derived) and it is complete or its diagnostics row has part 0 `Verified`. A resting row counts, so a restored download is ready before it resumes, and so is a failed one that kept the part. Read from the row each frame, never stored; the tail never gates.
_Avoid_: playable, preview available (aMule's `PreviewAvailable`, a byte-range query), head and tail verified

**Player Command**:
The operator's player: one text under the TUI's own key `player_command`, edited on the Settings tab, unset by default, and then Preview opens the **Default App**; set, it overrides that. Split POSIX-style at launch (`shlex`, no shell); every `%PARTFILE` inside a word becomes the **Download File Path**, else the path goes last; the first word is the program and never holds `%PARTFILE`, and written as a path it is never a folder — except a macOS application bundle (`/Applications/IINA.app`), which starts as `open -a <bundle>` and the other words, the app named, so LaunchServices never picks a handler by `.part`. Read at every launch.
_Avoid_: video player path, command line (a line implies a shell), viewer

**Default App**:
The app the operating system opens a download's real type with, which Preview starts when no **Player Command** is set (ADR-0114). Looked up on the player lane by the extension of the download's name, never of the file on disk (`.part`): LaunchServices on macOS, started as `open -a <app> <file>`; `AssocQueryStringW` on Windows, its executable run on the file; the freedesktop `globs2` and `mimeapps.list` files elsewhere, the desktop entry started by `gio launch`. A type with no app says so and points to the Player Command.
_Avoid_: system player, file association, open-with
