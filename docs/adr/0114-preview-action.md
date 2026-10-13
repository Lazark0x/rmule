# Preview hands a download's own file to the operator's player as one argument, once its first part is verified

## Context

An operator wants to look into a video or song before it finishes. The Transfers tab already
draws each download's part map from `DownloadDiagnostics::parts` (ADR-0079), and every
download it lists has that row, running or at rest (ADR-0094), so a download restored at
attach shows which parts it holds before it resumes. Its row menu greys an item it cannot
act on with the reason. Nothing in the TUI starts a process. Core names a finished file's
path on `DownloadCompleted`; the `.part` path is stored with the download record but reaches
no consumer, and no front end composes a path (ADR-0069).

aMule previews from its GUI (`DownloadListCtrl.cpp:1427-1485`). The menu item is enabled
when the name is video or audio, the file is at least 256 KiB and its first 256 KiB are
complete (`PartFile.cpp:3792-3800`, `DownloadListCtrl.cpp:743`). The player receives the
`.part` path, or the finished file's, never a copy (`DownloadListCtrl.cpp:1447-1455`). The
command is `/eMule/VideoPlayer`, empty by default (`Preferences.cpp:1156`); an empty one
warns and runs `xterm … mplayer` instead (`DownloadListCtrl.cpp:1432-1438`). `%PARTFILE` is
substituted into the command text, which gets the path appended in quotes when it has no
such word (`:1458-1465`); quotes in the name are backslash-escaped outside Windows, "otherwise
arbitrary options could be passed to the player" (`:1467-1472`), and the text goes to
`wxExecute` (`:1479`). aMule citations are to 2.3.3; read, never ported (ADR-0082).

## Decision

**Preview is the TUI's action. It hands the file core published for a download to the
player the operator set — with none set, to the app the operating system opens the
download's real type with — as one argument and through no shell, when core says the
download is Previewable and its first part is verified or the download is complete.
Core carries the facts and never runs a player.**

**Previewable is core's reading.** The TUI asks `DownloadMetadata::is_previewable()`
(ADR-0112's Previewable set, video and audio, read off the name's extension) and keeps no
extension table. A download whose name core never learned is not Previewable.

**Preview Ready** is Previewable and either `Completed`, or `parts[0] == Verified` on the
download's diagnostics row. It is read from the row each frame, never stored.

- A resting row counts (ADR-0094): a download restored but not resumed is ready from its
  resting row, and so is a failed one, which keeps its `.part` and its verified parts. No
  edge carries part indices for this; `DownloadProgressRestored` keeps its counts.
- A verified part 0 is 9,728,000 bytes, so it answers aMule's 256 KiB gate conservatively
  and no byte-range query is added. aMule's 256 KiB size floor is dropped: a smaller file
  whose part 0 is verified is complete.
- The tail never gates. ADR-0112's Preview Band fetches it early; a player that needs an
  index not yet on disk fails, and its exit note says so. The `.part` keeps each part at its
  own offset with holes where parts are missing (ADR-0111), so the player sees verified
  bytes in place.

**Core publishes where the bytes are.** `DownloadQueued` and `DownloadRecovered` gain
`file_path`: the `.part` of a download that is not complete, the finished file of one that
is, read from the stored record by one accessor. `DownloadCompleted`'s `final_path` moves
it. The TUI keeps it on the row and hands it on; it never joins the download directory and
the name, since the directory may have changed since the download started and the name's
bytes need not spell the path. `DownloadPaths` itself is not published: a completed row's
`.part` slot may have been released to a newer row and is then not a path. The Run Log
records `file_path` as a path, so at the full level only (ADR-0075).

**The Player Command is the TUI's own key** (`player_command`, ADR-0069): core never reads
it, so it is not a Core Setting, and as a front-end key it needs no store change. The
Settings tab edits it as text in the Downloads group. It is unset by default and takes
effect at once: every launch reads it.

- Empty clears it. A text whose words do not split (an open quote) is refused under the
  field, and so is one whose first word holds `%PARTFILE`, so the downloaded file is never
  the program run. A first word written as a path that names a folder is refused too,
  since no system runs a folder, unless on macOS it is an application bundle (below). A
  bare name is the system's to find on `PATH`, and a path not there yet is taken: the
  player may be installed later. The Settings commit and every launch read it alike.
- Unset, Preview opens the **Default App** (below), and a set Player Command overrides it.
  The file is never handed to an association launcher (`open <file>`, `xdg-open`, `start`):
  one picks a handler by the extension on disk, and the extension of a `.part` is `.part`.
  rmule looks the app up by the download's real name and names it.

**Arguments, never a shell line.** At launch the text is split into words by POSIX rules
(the `shlex` crate, ADR-0002): quotes and backslashes are honoured; nothing is expanded,
globbed or run as an operator, and a word starting with `#` comments out the rest. Every
`%PARTFILE` inside a word is replaced by the path, and that word stays one argument. With no
such word, the path is appended as the last argument. The placeholder is aMule's, so an
aMule player string carries over. aMule substitutes before splitting and so must escape;
rmule substitutes after, so there is nothing to escape. The path is absolute (core refuses a
relative download or Temp Directory, ADR-0115), so a player cannot read it as an option. The first word is
the program, run with standard input, output and error null; the terminal holds the TUI.

On macOS a player is an application bundle, a folder no exec runs, and that is what a Mac
operator picks (`/Applications/IINA.app`). A first word naming a folder called `.app`
starts through LaunchServices with the app named: the words become `/usr/bin/open -a
<bundle>` and then the other words, and `%PARTFILE` is placed by the same rules, inside a
word or else last. Named, the app is the handler; LaunchServices never picks one by the
`.part` extension. The other words are
`open`'s own: what follows `--args` goes to the app's `main` rather than being opened, so a
command with `--args` places `%PARTFILE` before it. Still arguments, never a shell line.

**The Default App.** With no Player Command, Preview asks the operating system which app
opens the download's real type, by the extension of its name: the bytes after the last `.`,
read as the file class reads them, so a name whose stem is not UTF-8 keeps its extension. The
app is started on the file core published, `.part` or finished, with no copy and no second
name on disk:

- **macOS**: LaunchServices. `UTTypeCreatePreferredIdentifierForTag` reads the extension as a
  type and `LSCopyDefaultApplicationURLForContentType` names its default app for any role;
  the launch is the bundle road above, `/usr/bin/open -a <app> <file>`.
- **Windows**: `AssocQueryStringW` with `ASSOCSTR_EXECUTABLE` for `.<extension>` and the
  `open` verb, the Unknown type ignored (`ASSOCF_INIT_IGNOREUNKNOWN`), so a type with no app
  answers that, not with the Open With dialog. The launch is that executable with the file as
  its one argument: no shell, no `start`. A packaged (Store) app that has no executable to
  run this way ends in a lookup or spawn note.
- **Linux and other freedesktop systems**: rmule reads the freedesktop files itself. The
  extension's MIME type comes from shared-mime-info's `globs2` files, user before system, the
  heaviest `*.<extension>` glob winning, case folded unless the glob is marked `cs`. The app
  comes from the MIME Applications spec's `mimeapps.list` files in the spec's order
  (desktop-specific lists first, config directories before data directories): the first
  installed entry listed under *Default Applications*, else the first under *Added
  Associations* or in a data directory's `mimeinfo.cache` that no list names under *Removed
  Associations*. The
  launch is `gio launch <desktop file> <file>`: GLib runs the entry's `Exec` by the Desktop
  Entry spec (field codes, quoting, `Terminal`), which rmule does not re-implement; a system
  without GLib's `gio` gets the refused-spawn note. rmule does not run `xdg-mime query
  default`: it is a shell script, the lookup would start a process, and a test could not hand
  it directories of its own.

The calls the standard library does not expose are `rmule-os`'s (ADR-0111), module
`default_app`, one waived function per call: on macOS `CFStringCreateWithBytes`, the type
lookup, the app lookup, `CFURLGetFileSystemRepresentation` and `CFRelease`; on Windows
`AssocQueryStringW`, from `windows-sys`'s `Win32_UI_Shell`. No crate in the graph declares
the two CoreServices calls, so each function that calls one declares it in an `unsafe extern`
block of its own, under its own `// SAFETY:` comment. The lookup runs on the player lane, never
on a frame. It is a short read, so the lane runs it through `spawn_blocking`; the wait for the
player still never does. A type the system has no app for notes and flashes *no app opens
.<extension> files here*, with the way out, a player set in Settings; a lookup the system
fails notes its error kind in the operator's words.

**A launch.** The view emits `Action::Preview(DownloadId)`. The reducer resolves the row,
the command and the path by the same reading the menu shows, so the two cannot disagree. It
then hands the arguments to a player lane, as it does the Kad start. A task on the app's
runtime spawns the player through `tokio::process` and awaits its exit. It never waits
through `spawn_blocking`, because the runtime's drop waits for blocking tasks, and an open
player would hold the TUI's exit. Quitting the TUI does not kill the player (`kill_on_drop`
stays off); on Unix the player gets a process group of its own, so the terminal closing
does not reach it. Nothing is tracked beyond the exit: a second launch is a second process.
A launch through `open` ends once LaunchServices has handed the file over, not when the
player quits; `open` exits non-zero when the app cannot open the file, and that status is
noted as any player's is.

**The control.** The Transfers row menu offers **Preview** under *Show file details*, and
`v` on the Transfers table does the same, bound on that tab alone (ADR-0074). The first
state that holds decides:

| State | Menu item | `v` |
| --- | --- | --- |
| name or file path not known yet | greyed, *details not known yet* | flashes the reason |
| not Previewable | greyed, *not a video or audio file* | flashes the reason |
| no Player Command and no extension on the name | greyed, *no app for this type* | flashes the reason |
| no diagnostics row in the last snapshot | greyed, *part map not loaded yet* | flashes the reason |
| part 0 not verified and not `Completed` | greyed, *first part not verified yet* | flashes the reason |
| Preview Ready | launches | launches |

A refused spawn flashes and notes *the player could not start* with the OS error kind in
the operator's words, a denied permission as *the program is not executable*; a non-zero exit notes its status; an end by signal says so; a zero
exit says nothing. Each note names the download. Every reason and note is written in the
TUI's words from a code (`words/player.rs`); no type name or Debug output reaches the
operator.

**Windows.** No shell is in the path there either. The standard library builds the child's
command line by the MSVC quoting rules, which a `.exe` parses back into the same arguments;
a `.bat` or `.cmd` player runs under `cmd.exe`, where it escapes each argument or refuses
with `InvalidInput`, and the refused-spawn note says so. A Windows name cannot hold `"`.
Split by POSIX rules, a path with backslashes in the command goes in single quotes.

## Consequences

- Core gains one field on two edges and one record accessor. It has no player code and no
  setting for one.
- A player is outside rmule. One that writes to or truncates the `.part` is caught by the
  run's checks like any other change (ADR-0094, "The run holds its part file").
- On Windows a player holding the `.part` without delete sharing holds up the completion
  move: the download stays Completing, "waiting for the file to be released", and completes
  on its own once the player closes (ADR-0115).
- A player that sniffs only the extension may refuse a `.part`, the Default App among them;
  a Player Command then names one that reads the content.
- A completed file moved or renamed after it finished keeps its old path on the download
  record, which is never rewritten; its Preview hands the player a path that is gone, and
  the exit note says the player failed.
- Not built: preview from Shared Files, a per-download preview flag, in-app playback, any
  tracking of a player beyond its exit.

## Considered options

- **The command as a Core Setting.** Rejected: core never reads it, and a key core does not
  act on is the front end's (ADR-0069).
- **`DownloadPaths` on the edges.** Rejected: a completed row's `.part` slot may be
  released, a stand-in rather than a path, and a consumer would be handed it.
- **The path on the diagnostics level.** Rejected: it is fixed for the download's life but
  for completion, which is already an edge, and a level would republish every path each
  second for one reader.
- **The positional vector on `DownloadProgressRestored`.** Rejected: the resting
  diagnostics row already carries it.
- **A shell line with escaping, as aMule does.** Rejected: escaping is the fix for a parser
  that sees the path; rmule's never does.
- **Copying the verified head to a temporary file.** Rejected: gigabytes of copy for what
  the `.part` already holds in place.
- **A hard link or symbolic link with the real name beside the `.part`.** Rejected: a second
  name on disk, to make and to clear away, when naming the app reaches the same handler.
- **Handing the file to `open`, `xdg-open` or `start`.** Rejected: each picks the handler by
  the extension on disk, `.part`.
