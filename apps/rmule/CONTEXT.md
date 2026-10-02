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
What the Networks log, the status bar's note and a flash hold: a line the TUI wrote from a code core handed it, in the words modules (`crate::words`, one per domain, each an exhaustive match over its codes). Only the words modules can make one, so no `Debug` dump and no core type's `Display` reaches those surfaces; `scripts/guards.sh` refuses a Debug format anywhere else in the TUI's source outside tests and `tracing` calls, and a glyph golden refuses to render `Some(`, `None`, a struct's braces, a Rust path or a byte array. An address reads `host:port`, a hash or a Kad id as its short hex form.
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

**Run Log**:
The file in the data directory (`rmule.log`) every run appends its **records** to — always on, because the terminal is the alternate screen and a defect met in an ordinary session must leave evidence. A record is an event code plus typed fields, each field added by what it is (own address, peer address, file name, file hash, port, count, code). It is written at one of two **levels**: **lean** by default (reachability evidence — own addresses, ports, the port mapping, the server endpoint, login steps, verdicts — and codes, no peer address, file name, path or hash) or **full** by the preference *Full run log*, which adds the rest and also lets free-form `tracing` lines through. Search text and File History paths are never written. Bounded: at 16 MiB it is moved aside as the single predecessor `rmule.log.1`. `RMULE_LOG` is the filter; the default level is `info`. Even lean names the operator's own addresses, so it is the operator's to share; full names peers and files.
_Avoid_: debug log, trace file, console, verbose log

**Table Sort**:
The one column a table is ordered by, and its direction — view state, never core's. Every visible column can hold it and nothing else can; the header of the column holding it carries the arrow. Each table has one, kept across runs. Rows re-order as they change, and the cursor stays on its row rather than its position. A column may rank its rows into groups before its value (Transfers' Progress: moving bytes, then completed, then the rest); reversing reverses the value inside each group, never the groups. A table lists each column once — its stored key, header text and kind — so none of the three is a switch of its own.
_Avoid_: ordering, ranking, sort mode, sort key (a key with no column)

**Row Selection**:
What selecting a row is in every table: the cursor on a row's identity (`RowCursor`), moved by `j`/`k`/arrows and `g`/`G`, and the one mark it wears — the `▸` gutter marker and the selection background across the row, bold in the focused pane and dimmed, never hidden, in a pane without the focus. A click selects and focuses; `Enter`/`m` open the menu on the selected row. Settings' form fields are not rows.
_Avoid_: highlight, cursor row, active row, current row

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
