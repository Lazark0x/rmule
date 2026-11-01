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
The bridge's 1 Hz poll: read `diagnostics_snapshot()`, synthesize transfer rates, patch in the Kad facts the sync accessor cannot see, and publish the result as one snapshot action. The only clock the UI core has — every time-bearing fact is stamped with the tick's injected instant, never a wall clock read at render. The one wall reading is the app loop's, handed to the **Log** before each action lands.
_Avoid_: refresh, frame, poll loop (the render loop is separate and runs at its own pace)

**View state**:
What a view owns: selection, scroll offset, focus, which modal is up, what has been typed into it. Never data — a view that held a copy of a download row could show a row core does not have. The split is what lets every view test as a pure function of `(UiState, view state, now)`.
_Avoid_: model, local state, component state

**Honest degrade**:
Rendering a fact core does not surface as a visible absence — the word for its state, or a control greyed *with its reason* — rather than a zero, an invented name, or a hidden control. Each state has its word (`words::absent`): unknown, not running, not measured, no name, none. A measured zero is no absence and reads as a zero. An action that would be rejected says why it is unavailable. A cell too narrow for its word draws `—`, the one thing that mark means, and the word rides the **Off-screen line**. The columns and controls stay because the spec pins the set; the word is the honest state until core carries the fact.
_Avoid_: placeholder, empty state, fallback value (a fallback invents; a degrade admits)

**No dead UI**:
The rule honest degrades serve: every control the chrome offers does something, and every fact it shows was observed. A control that cannot work is greyed with its reason, not silently inert.
_Avoid_: disabled control (that is the mechanism, not the rule), stub

**Glyph golden**:
A render snapshot compared glyph-exactly against `tests/goldens/<name>.txt`, drawn through ratatui's `TestBackend` at a fixed size with trailing whitespace trimmed. Goldens are recorded evidence of what the view draws: they are re-blessed deliberately (`UPDATE_GOLDENS=1`), never as a way to make a failing test pass.
_Avoid_: snapshot test (too generic), screenshot, visual test

**Help**:
The `?` overlay: the tab the operator came from first, then what every tab shares, the other tabs, and a Words table for the terms and bracketed figures the screens use unexplained, and a table of the Known-File Marks that says what this theme shows. Letters type into its **Row Filter**, so `↑`/`↓`, the page keys, `Home` and `End` scroll it, `Esc` takes the text before it takes the overlay, and `?` closes it while nothing is typed.
_Avoid_: manual, cheat sheet

**Capability**:
What a run's terminal can show, read once at the start from the environment and the terminal's answers to the probe (`capability`, `probe`): a colour tier (truecolor, 256, the sixteen named colours, none), whether its ground is light, and a **Glyph Tier**. The probe asks for the background (OSC 11), measures one box-drawing character by a cursor report, and asks device attributes last, so that answer ends the wait. It is the run's one question: it goes through the **Line** before the loop starts, the loop asks nothing, and a stop's re-entry keeps the answers, since `fg` finds the same terminal. A terminal that stays silent costs a bounded fraction of a second and then draws; input waits a little longer for a late answer, which would otherwise arrive as keys, and the operator's own keys among what it read go on as input. A terminal that says what its ground is keeps it and gets the palette for that side; one that does not gets the opaque palette its pairs are known to read on. `TERM=dumb` is refused before any of this.
_Avoid_: terminfo, feature detection

**Glyph Tier**:
Which glyphs a frame ends in (`glyphs`). Views draw one set; the tier rewrites the finished frame cell for cell, so no view holds a glyph choice and nothing moves. **Plain** replaces the frame's marks and typographic signs with ASCII and keeps the operator's text, for an ambiguous-wide terminal and the Linux console; **Ascii** also turns all other text to `?`, for a terminal not reading UTF-8. The measure beats the locale: `LC_ALL=C` on a UTF-8 terminal stays Unicode.

**Reader Mode**:
The Settings preference for a screen reader or braille display, off by default: the terminal's cursor rests on an open menu's item or the focused pane's selected row, and the data tick repaints nothing on its own, so a screen with nothing new does not change: its figures and ages wait for news or a key. `rmule-cli` remains the plain path.

**Chrome**:
Everything around the views: the tab bar, the status bar and its width budget, the help overlay, the flash, the mouse's capture, and the terminal's title and bell when the operator asks for them. It owns no core data — it reads the same `UiState` the views do.
_Avoid_: layout, shell, frame — as names for the chrome. `Frame` stays ratatui's word for the surface being drawn into, so `draw_frame(frame: &mut Frame, …)` reads right.

**Status bar**:
The bottom border's one row, which answers "is everything fine?" at any width and takes no rows from the frame. The rates sit first, in fixed cells, and are never pushed off: nothing else claims the row before them, and below 29 columns they read in a short form. What is left goes by claim: a flash or a stopped core, the way to help, the connection, the **Tally**, the note, the server's users once it has reported them; a segment is dropped whole, except a flash and a note, which give up their middle. While a text field or help holds the keys the way to help reads `Esc leave`. The connection reads off edges, as the Servers title and its `c` hint do, so they agree in every frame: a dial is `connecting…`, off is dim when chosen, red when lost.
_Avoid_: footer, status line

**Log**:
The Networks pane that says what happened, every line a **Sentence** with the local time it was said at, stamped as it arrives so a machine's sleep moves nothing. A date line opens it and each new day; scrolled past one, the day stands on the bottom border. Two rings in fixed memory, read as one in the order said: the everyday lines and the warnings and failures, so a chatty login cannot push a failure out. All of it lasts one run; the Run Log is what outlives it.
_Avoid_: console, event list

**Severity**:
How much a **Log** line asks of the operator: info, warning, failure. Read from the event's code (`rmule_words::severity`), never its words, and listed for every event; what a stranger can cause at will is info, whatever it says, so a peer cannot fill the warnings' ring. Drawn as a glyph, with the word opening a warning or a failure, never as colour alone. `f` on the focused log walks every line, warnings and failures, failures.
_Avoid_: level, priority (a download's)

**Rate history**:
What the Statistics graphs plot, in fixed memory: ten minutes tick by tick, a day of minutes, a month of hours, stamped on the **Data tick**. A coarse column is the mean of its ticks, so its area is the bytes moved; a span no tick landed in stays blank beside a metered zero, which keeps a floor. `w` walks the window, what a column stands for; a graph never resamples, so a wider pane sees further back. All of it lasts one run.
_Avoid_: graph buffer, samples

**Tally**:
What the Transfers table adds up to: active, failed and done, each counted only when not zero, on the status bar and in the terminal's title. A count at the bar's right end moves nothing but itself.
_Avoid_: summary, badge

**Note**:
The status bar's last notable fact, newest wins. It stands five minutes, saying its age once it is a minute old, and its line stays in the log. A pause, a resume and an added download each leave one naming the file, the receipt that replaces whatever was there.
_Avoid_: status text, toast

**Tab**:
One of the six top-level surfaces the chrome switches between, named by `ViewId` and drawn in the tab bar. A tab is what the operator selects — a digit, `h`/`l`, `←`/`→`, or a click; the **view** is the component that draws it, and exactly one is active at a time. The tab left up is what the next run opens on. The bar names every tab down to 75 columns, two of them by a short title. What the chrome hands that view is a content rect, never the whole frame.
_Avoid_: page, screen, window

**Pane**:
A bounded region *inside* one view's content rect: the server table, the log and the Kad panel in Networks; the files and upload-peers halves of Shared Files. Focus inside a view lives at pane granularity — the focused pane takes the navigation keys, everything else bubbles to the globals. A view caches each pane's rect at draw time, so a click is hit-tested against the layout that was actually drawn rather than one recomputed from a stale width. A pane's title and its key hint share its top border and give way whole when it is narrow — the hint's keys first, last first, then the title's clauses, last first — never cut mid-word, so a hint leads with the keys a person needs first. Two panes stack by share and stand side by side from 160 cells; one with nothing to list takes the lines it says that in (`views::panes`).
_Avoid_: section, widget, subview

**Zoom**:
`z`: the focused pane takes the whole tab and the other draws nothing and takes no click, until `z` again. `Tab` carries it across; Searches gives its results the tab and drops the zoom when the query is asked for.
_Avoid_: maximize, fullscreen

**Too-small screen**:
What a terminal under 60×20 shows in place of the tab: its size, the size rmule needs, and `q`. No view is on show, so no view hears a key; only the way out answers (ADR-0119).
_Avoid_: minimum size error

**Key gate**:
The one reading of a key's kind and modifiers, at the reducer before any view: a release and an unbound Ctrl or Alt chord act on nothing, Ctrl-C takes the quit path, Ctrl-Z the job stop and Ctrl-L the full repaint from every surface, and Ctrl with Alt on a character is AltGr, which is text. While a **Line Edit** holds the keyboard the chords it binds pass, and it alone reads them; every other view reads key codes alone. Outside one `Ctrl-D` and `Ctrl-U` are read as `PgDn` and `PgUp`, so none reaches a view as its letter.
_Avoid_: per-view key filter

**Line Edit**:
The one line editor under every text field: a caret on a grapheme boundary, the arrows, `Home`, `End`, word moves, delete both ways, readline's cut and yank keys, and paste at the caret. It scrolls sideways around the caret, measured in terminal cells, with `‹` and `›` where text lies past an edge, and the terminal's real cursor sits at the caret so an input method composes in place. A field holding the keyboard is one line; left alone it wraps whole. No input loses its text: a refused submit keeps it with the reason under the field, and a Settings field stays open, `Tab`, the arrows and the wheel staying on it, until the store has the value.
_Avoid_: text input, input box, prompt

**Directory Field**:
A **Line Edit** that names a directory: a leading `~` is the operator's home, `Tab` completes from the disk and says what is left to choose from, and a path with nothing at it is said before it is set: a Download dir or Temp dir that core would make asks a second `Enter` under the warning's `!` mark, never the refusal's `✗`, and a directory to share is refused.
_Avoid_: path picker

**Stop**:
The value every way out of a run sets, from any thread and without blocking: a signal, the terminal's loss, the input pump's end, the operator's quit. It wakes the loop, starts the core's quit from its own task and arms the deadline that ends the process, so a stop depends on neither the loop nor the terminal (ADR-0118).
_Avoid_: shutdown flag, exit path

**Line**:
The one thread that writes to the terminal. A frame it is not ready for is held, whole, and a failed write is the terminal's loss, told to the Stop and never returned as an error (ADR-0118).
_Avoid_: writer, render thread

**Quit Confirm**:
The chrome modal that asks before `q` or Ctrl-C stops what is under way, and counts it: a download moving bytes or waiting, an upload, a peer in the upload queue. `y` or a second Ctrl-C quits, `n` or `Esc` stays. A truly idle app, paused downloads at most, does not ask, and an OS stop never does.
_Avoid_: exit prompt

**Row Filter**:
`/` in every list (`row_filter`): every table, the log and Settings narrow to the rows that hold what is typed, as it is typed, on the one **Line Edit**; each typed word must be found, case and accents folded, in the row's text columns. `Enter` keeps the filter and hands the keys back, `Esc` clears it, and the arrows and page keys move the list meanwhile. Its line, at the foot of the list, says how many rows hold it. On Searches `/` reaches the query while no result is on show and `i` always does. Help filters the same way, from the moment it opens.
_Avoid_: search (a search asks the network), find

**Tags**:
The rows of a table an action takes together (`row_selection::tags`): `Space`, `T`, and `•` in the gutter. `p`, `x` and the **Row Menu** act on them, else on the row under the cursor, and an item that can only take one row greys with that reason. Tagged rows survive a Row Filter, and `P` on Transfers acts on every row on show.
_Avoid_: selection (that is the cursor's row), marks (a **Known-File Mark** is something else), multi-select

**Row Menu**:
The one action list every table opens with `Enter` or `m` (`views::menu`): titled by the row it acts on, never a hash. An item is enabled, or greyed with its reason, which the cursor skips. The list wraps at its ends; `m`, `q` and `Esc` close it; an item shows the key that runs it from the table, and that key runs it from the open menu too. A click runs an item, a click outside closes the menu.
_Avoid_: context menu, popup

**Question**:
The one confirm before an action that takes something back (`views::modal::draw_question`): what it is about by name, the file or the server, or by count; never a hash; what a yes does; and the one answer pair, `y yes` and `n no`. `x` is the row's way out in every table, a cancel, an unshare, a removal, and it asks one. `Esc` and `q` answer no, except a share question, which waits for `y` or `n`.
_Avoid_: dialog, alert, prompt

**Revision**:
A number on the UI state that moves whenever a fold changed something. A table's order stands on it, with the table's own sort and filter, so a wheel notch over ten thousand rows rebuilds nothing.
_Avoid_: generation, dirty flag

**Flash**:
A transient one-line message the app loop shows and expires — how a view reports something it could not do, in the accent, never the warning's amber. It takes the status bar's row beside the rates, gives up its middle when long, and its whole sentence goes to the log. Distinct from the **Note**, which carries the last notable *core* fact and is folded into `UiState`. One caller is not a view: `App::graceful_quit` fires it directly and event-driven, never on a timer — the opening "Shutting down…" before any step starts, then one redraw per `CoreEvent::Quitting { step }` action naming the step actually running, and, if the bridge's `CORE_SHUTDOWN_GRACE` elapses before the core's flush confirms, one more naming that.
_Avoid_: toast, alert, error message

**View outcome**:
What a view did with an input it was offered: ignored it (bubble on to the global bindings), redrew, or emitted an action. The one shape every view returns, so the app loop's dispatch is the same for all six.
_Avoid_: event result, handled flag

**Sentence**:
What the Networks log, the **Note** and a flash hold: a line written from a code in a words module — `rmule-words`, whose glossary owns the term, or the TUI's own (`crate::words`, which re-exports the shared modules under the same names and adds the sentences that word the TUI's own types: its command line, a run with no core, a Settings edit, a server-health edge, a search entry's paging, the share set's tally, a preview's reasons and notes). `scripts/guards.sh` refuses a sentence made, or a Debug format, anywhere else in the TUI's source outside tests and `tracing` calls, and a glyph golden refuses to render `Some(`, `None`, a struct's braces, a Rust path or a byte array.
_Avoid_: message, string, label (a label is a word in a cell; a sentence is a line said)

**Drawn word**:
Any text a module that draws puts on screen: a label, a title, a hint, an empty state, a unit. Every one comes from a words module, so a language can replace it, and none is decided on or sorted by. `scripts/drawn-words.py` refuses a string literal holding a letter in `views`, `chrome`, `form`, `table`, `row_selection`, `row_filter` and `view.rs`, with no allowance; what is stored, never drawn, is a **Stored key**.
_Avoid_: hard-coded string, literal

**Stored key**:
What a kept tab and a kept **Table Sort** are written under (`stored_keys`). Stable, never drawn and never translated: renaming one forgets an installed value.
_Avoid_: label, column name

**Hint**:
A key and what it does (`words::hints`), on a pane's border and under a form. Every pane's hint is a list of them two spaces apart, in the order they give way, so a key is never part of a word.
_Avoid_: legend, shortcut

**Plural**:
A phrase in every form a language gives it, `{n}` where the count goes (`rmule_words::plural`): the only way a word is chosen by a number. A count names its form by the language's CLDR category, never by `n == 1`.
_Avoid_: noun pair, singular

**Off-screen line**:
The one line at the bottom of a table that says what the selected row does not show: the value of every column that gave way and the whole of every value a cell cut or shortened, as `Label value`, above the border's note naming the hidden columns — every table the same way (`views::off_screen`), so a row on one line never loses a value (ADR-0119). It wraps, up to half the table, and holds as many lines as any row on screen would ask for, so the frame stands still as the cursor walks them.
_Avoid_: detail row, tooltip, footer

**Greedy width**:
A table's column budget (`table::greedy_widths`), one line per row. Each column has a floor it is shown at or not at all, measured from its header and the words and units it draws, so a language whose words run longer widens the column rather than cutting them; only digits and free text keep a floor in cells. The greedy column — the one holding free text; Servers has two — takes the slack left after the bounded columns (an endpoint, a phase, a rate) have asked for the widest value they show, up to a cap. Its floor is the room it keeps: a pane that cannot hold every floor takes columns away in the table's stated give-way order, the greedy column never, and says on its bottom border which, or how many, are not shown. A header is never split: no column is narrower than its header and the sort arrow. Numbers and rates sit right, words left, by the column's kind.
_Avoid_: fixed layout, shrink, wrap (a row does not)

**Middle cut**:
What free text does in a cell too narrow for it (`table::cut_middle`, ADR-0119): its start and end around `…`, the file extension kept, measured in display cells and walked by grapheme cluster, so a wide glyph or a combining mark is never split. A figure with a shorter form draws that first. The whole value rides the **Off-screen line**.
_Avoid_: truncation, ellipsis, clipping

**Stalled**:
What a Downloading row says when its received bytes have stood still for 30 seconds (`UiState::download_stalled`, from `TransferRates::download_quiet`, the counter's own last move): the row holds a slot or an assigned part, and nothing arrives. Green is kept for bytes moving, so it reads plain, ranks with the waiting rows in Progress's activity groups by that fact, and keeps Downloading's rank under Status.
_Avoid_: idle, hung, frozen

**Data directory**:
What the app resolves before anything else, by core's rule (`--data-dir`, `RMULE_DATA`, then `$XDG_DATA_HOME` or `$HOME` on Unix and `%LOCALAPPDATA%` on Windows): rmule's Durable Store (`rmule.redb`, ADR-0083) and the data files beside it (`clients.met`, `nodes.dat`, the IP filter). The TUI opens that one store and hands its seams to the embedded core, so a directory carries exactly one running client — the engine holds the file lock.
_Avoid_: profile, workspace, config dir (the config is a seam of the store, not a file of its own)

**Table Sort**:
The one column a table is ordered by, and its direction — view state, never core's. Every visible column can hold it and nothing else can; the header of the column holding it carries the arrow. Each table has one, kept across runs; until the operator picks one a table opens by name, or by the fact it is read for: Transfers by Progress, Searches by Sources. Rows re-order as they change, and the cursor stays on its row rather than its position. A column may rank its rows into groups before its value (Transfers' Progress: moving bytes, then completed, then the rest); reversing reverses the value inside each group, never the groups. A table lists each column once — its stored key, header text and kind — so none of the three is a switch of its own.
_Avoid_: ordering, ranking, sort mode, sort key (a key with no column)

**Row Selection**:
What selecting a row is in every table: the cursor on a row's identity (`RowCursor`), moved by `j`/`k`/`↑`/`↓` and `g`/`G`, and the one mark it wears — the `▸` gutter marker and the selection across the row, a background or, with no fill to spare, reverse video; bold in the focused pane, plain and still marked (underlined where it has no fill) in a pane without the focus. `PgUp`/`PgDn` and `Ctrl-U`/`Ctrl-D` move by the rows on screen and `Home`/`End` to the ends, in one place (`RowMove::of`), so every table, the log, the Settings rows and a modal that only reads move alike. A click selects and focuses; `Enter`/`m` open the **Row Menu** on the selected row. Settings' form fields are not rows.
_Avoid_: highlight, cursor row, active row, current row

**Viewport**:
What part of a scrollable list is on screen — its first item, how many items the last draw showed whole, and of how many — owned beside the **Row Selection** (`row_selection::viewport`), written by the draw, and the one source of the list's scroll bar and count. In a list with a cursor it follows the cursor, moving no further than keeps it on screen; in one without (the log, the help, the file details modal) it stays where it was scrolled, and one resting on its end keeps the end in view. While the list overflows, the bar (`▲` `▼` at its ends, a `█` thumb on a track column of its own colour, the thumb's edges in eighths of a cell; whole cells on a `║` track where the theme has no distinct thumb colour) takes the inner right column; the bottom border's right end says the cursor's row over the rows — or, while it overflows, the last item on screen over the total — and that count gives way last.
_Avoid_: scroll offset (one fact of it), scroll state, window, page

**Natural Direction**:
The direction a column takes when it first receives the **Table Sort**: ascending for text and for ranks (a word standing for an order: a type, a status, a priority), descending for quantities.
_Avoid_: default direction, initial order

**Tie Chain**:
What orders two rows the sort column holds equal: name ascending, then the row's identity. It makes every order total, and reversing the **Table Sort** never reverses it.
_Avoid_: secondary sort, stable sort, sort history

**Known-File Mark**:
What a search result says about the operator's own history with its file: **Downloading**, **Failed**, **Have**, **Withheld**, **Had** or **Cancelled**, at most one, in that precedence; no mark means the file is new to them. Drawn as the row's colour and a text attribute, in place of the source-count tint, with its word opening the Name cell; the help overlay's marks table says what each means and shows. **Have** takes its attribute only in a theme with no colour.
_Avoid_: file status, known flag, File-Known Predicate (core's serving gate, a different question)

**Held Search**:
One search the Search tab is keeping: its query, its status, its live **Search Result Set** and its own cursor. Its status line names each leg of the search in the TUI's words — server, other servers, Kad: waiting for a connection, waiting for Kad, searching, done, not asked / not running, not answered, and not sent with its reason — no server, no Kad contact answered, another Kad lookup holds the word, no word of three letters; a completed search names any leg that ended so beside its count. Any number are held side by side, each an entry on the strip under the query input; one not in view keeps receiving results. It lasts until the operator closes it, `u` bringing the one closed last back, or the run ends — nothing of it is written to disk.
_Avoid_: search tab (the Search tab holds them), search history, saved search, session


**Autoconnect**:
The Settings preference, on by default, under which the app sends at start the same `ConnectToServer` the `c` key sends, to the server last connected to (recorded on every `Connected` edge) — once, to that server alone (ADR-0095, "Connecting is the operator's act"). A first run has no such server and dials nothing. An unset key reads on; a stored off stays off. Nothing else in the app dials a server; with it off, a start connects to nothing and the Kad join waits for the operator's connect.
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
