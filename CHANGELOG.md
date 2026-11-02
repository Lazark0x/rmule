# Changelog

All notable changes to rmule are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-11-02

Part files stay sparse and live in a Temp Directory, a download can be previewed
and shared while it runs, and the terminal client is rebuilt around one way of
typing, finding and acting. Under that, every rule rmule keeps with its peers was
read again against aMule, and arrived data now survives a pause, a quit and a
restart.

### Upgrading

- The store moves to version 19 at the first start, and earlier versions of rmule
  then refuse it. Copy the data directory first if you may want to go back.
- A store from before the first release needs one start of rmule 0.2.0 first; see
  Store below.
- Autoconnect is now on by default, and Shared Files' upload filter moved from `a`
  to `f`.

### Bootstrap

- A release carries a seed list. A first start lists its servers before any
  fetch, and Kad dials its nodes first, so a mirror that fails or is forged
  cannot leave rmule with nowhere to go or choose every server for it.
- A fetched list adds to the seeds and never replaces them, and a list of a
  shape no mirror serves is refused whole.
- A fetched `nodes.dat` gives addresses to dial, each of which must answer
  before it reaches the routing table.
- A redirect from `https` to `http` is refused.

### Terminal UI

- Every text field has a caret, readline keys and the terminal's own cursor, so
  an input method composes in place. A path field takes `~` and completes on
  `Tab`.
- `Enter` on a search moves to its results, and `u` brings back the search
  closed last.
- No field loses what was typed: a refusal stays under it, with the text.

### Words and numbers

- Every label, title, hint and empty state comes from a words module, so the
  app can be translated; a guard holds it. A count picks its form through one
  plural seam, and a column's floor is measured from the words it draws.
- A value with none says which: unknown, not running, not measured, no name or
  none. A measured zero reads as a zero, and `—` is only what a cell too narrow
  for its word draws.
- Counts round to the nearest: 1,999,999 reads `2.0M`, not `1M`.
- A first run no longer says the last run failed, and a bad data directory
  names its path and the real cause.
- A scan's receipt says what it added and only the exceptions.
- Key hints read one way on every pane.

### Log and Statistics

- The log dates itself, marks each line with a glyph and a word for warnings and
  failures, and keeps those in a ring of their own, so a chatty login cannot
  push one out. `f` on the log narrows it by severity.
- A line keeps the time it was said, across a machine's sleep.
- Statistics keeps ten minutes of seconds, a day of minutes and a month of hours
  in fixed memory. `w` walks them, and Session says how long the run has been up.

### Keys and finding

- `/` filters the focused list as you type, every table, the log and Settings
  alike; `Enter` keeps it, `Esc` clears it. On Searches it filters held results,
  and `i` reaches the query.
- `PgUp`, `PgDn`, `Home`, `End`, `Ctrl-D` and `Ctrl-U` move every list, and `←`
  and `→` change tabs where no field claims them.
- `Space` and `T` tag rows; `p`, `x` and the row menu act on the tagged rows, and
  `P` pauses or resumes every download on show.
- `?` opens on the current tab's keys and narrows as you type, with a table of
  the words, marks and bracketed figures the screens use.
- Every row menu wraps, closes the same way, shows its keys and takes clicks;
  every confirm names the file or the count, never a hash, and answers `y` or
  `n`. `x` cancels, unshares or removes a row, and asks first. Shared Files'
  upload filter moved from `a` to `f`.
- A search result you know says so in a word, not only in colour.
- `q` asks while a download waits, an upload runs or a peer is queued.
- The wheel scrolls the pane under the pointer. A Mouse setting and `--no-mouse`
  leave the mouse to the terminal; help says what that costs.

### Status bar and start

- The status bar always shows the rates, in fixed cells and a unit that adapts
  past KB/s. Notes leave it after five minutes and stay in the log; a long note
  or flash shortens in its middle and never takes a row from the table.
- A tally of active, failed and done downloads sits on the bar. The last tab
  comes back at the next start.
- Settings can write rates and the tally to the terminal's title and ring the
  bell when a download finishes; both start off.
- A dial reads `connecting…`, a chosen off is dim, a lost connection red, and a
  flash no longer wears the warning's amber.
- Eighty columns name all six tabs.
- Autoconnect is on by default and dials the last server you connected to,
  nothing on a first run. If you turned it off, it stays off.

### Transfers

- Part files are sparse where the file system allows.
- Parts are fetched by availability inside a streaming window, down to the
  block, with a bounded end game.
- Arriving blocks reach the part file as they land, behind a write cache of
  64 MiB. Pause, quit and a restart keep them, so nothing that arrived is fetched
  again, and a bad block still fails its part. A download's memory no longer
  grows with the parts in flight.
- Quit gives each download up to 15 seconds to finish writing.
- A file is shared from its first verified part, and a queued or paused
  download is offered again once it passes the offer check after a restart.
- Preview hands a download's file to your player.
- A Temp Directory holds part files, and `rmule-cli config set-temp-dir` sets
  it. Completed files move out of it when they finish.
- A file past eD2k's 256 GiB limit is refused by the scan, unread, with its size
  and the limit. A row stored before this rule is withheld.

### Peers

- One peer holds one link and one place in a queue across several downloads,
  and rmule asks each source on one clock.
- A malformed frame costs a link exactly where aMule's handler says it does: rmule
  keeps the link on frames aMule tolerates, and closes it on frames aMule does
  not. The log says why a link closed.

### Speed

- Shared Files stays near 1 ms a frame at 10,000 rows while traffic moves, and
  every sorted table rebuilds only when what it reads has changed. Counters and
  speeds now move on every tick, not at the next event.
- A long search list takes its results in a fraction of the time.
- Work on a download's sources follows what changed, not how many there are, and
  a terminal that stops reading holds about 12 MiB rather than 69.

### Terminal

- Closing the window or losing ssh ends rmule with its usual quit, and no
  crash report; a terminal that stops reading no longer holds a stop.
- Ctrl-Z stops rmule as a job, and `fg` brings the screen back and says the
  transfers stood still. Ctrl-L repaints.
- SIGQUIT, SIGUSR1, SIGUSR2 and SIGALRM quit and give the terminal back. A
  crash restores the cursor.

### Store

- A store written before the first release is refused with its version and the
  oldest one this build upgrades, and is left as it was: open it once with
  rmule 0.2.0, which upgrades it.
- A scan commits its files many at a time, so a first scan of thousands of small
  files no longer stalls the app.
- A download whose stored link is damaged says so, rather than blaming a part.

### Interop harness

- Every flow writes one typed verdict to one TOML file, and the harness exits
  non-zero on `FAIL`. A run that wrote no verdict records `unknown`.
- A partial-share `PASS` needs every claim the run owes and a fully read wire.
  A sentinel run that drives no aMule reads `OBSERVED`.
- Base images are pinned by digest.

## [0.2.0] - 2026-10-13

An internal rework: each fact now has one owner across downloads, reachability,
Kad, settings and the wire.

### Changed

- Download sources live in one record per source, with one intake and one clock
  per file for purging them.
- A called-back Low ID source is pinged at the address it called in from, and
  queued sources are asked again only while connected.
- Core owns its settings through one handle, and the obfuscation policy changes
  live on every surface.
- Server UDP aims at the standard port; datagrams other than the crypt ping are
  sealed to the obfuscation port, which is read from the login answer and from
  `server.met`.
- `OP_OFFERFILES` follows aMule's per-server rule, completeness markers
  included.

## [0.1.0] - 2026-10-02

The first public release.

### eD2k servers

- Log in to an eD2k server over TCP, plain or obfuscated, with a High ID or a
  Low ID.
- A managed server list that keeps each server's name, priority, static pin
  and failure count; add servers one by one or update the list from a
  `server.met` URL. While the list is empty, a `server.met` is fetched at
  start, and a setting turns that off.
- Server UDP: global search, global source requests and status pings to every
  listed server.
- A lost server session is made again while you still want to be connected;
  nothing dials a server until you connect or turn on Autoconnect.

### Search

- One search goes to the connected server, to the other servers over UDP and
  to Kad at once, and the results merge.
- Filters for file type, size, sources and extension; more results from the
  server on request; related-files search.
- Every result says whether you already have, are fetching, failed, had or
  dropped the file.

### Downloads

- Downloads from many peers at once, assembled block by block, with AICH
  recovery of corrupt blocks.
- Sources from the server, server UDP, Kad, source exchange and the `ed2k://`
  link itself.
- Low-ID sources reached by callback: through the server, through a Kad buddy
  or by a direct UDP request.
- Pause and resume; downloads, their verified parts and their known peers
  survive a restart.

### Uploads and sharing

- An upload queue with Secure User Identification and credits, kept in
  `clients.met` as eMule and aMule keep them.
- Queue standing survives a disconnect, kept by UDP reasks.
- Shared directories: whole and recursive, hashed one file at a time and
  watched for changes. Finished downloads are shared.

### Kad

- A full Kad2 node: bootstrap from `nodes.dat`, routing, keyword search and
  publishing, source lookup and publishing, firewall checks, and buddies for
  Low-ID nodes.

### Connectivity

- Protocol obfuscation for peer TCP, peer UDP, Kad and server UDP under one
  setting.
- IPv6 in the dialect emule-qt speaks.
- Port mapping with PCP, NAT-PMP and UPnP, on by default, with a setting to
  turn it off.
- An IP filter read from `ipfilter.dat` and `ipfilter_static.dat` in the data
  directory.
- NAT traversal in the dialect eMuleAI speaks.

### `rmule`, the terminal client

- Six tabs in aMule's order: Networks, Searches, Transfers, Shared Files,
  Statistics and Settings.
- Keyboard and mouse control, sortable tables, a help overlay, and dark,
  light and 256-colour themes.
- A Run Log, `rmule.log`, at a lean level or a detailed one.

### `rmule-cli`, the headless client

- `identity show`, `server add` and `server list`, `config set-download-dir`
  and `config show`, `add` for an `ed2k://` link, and `kad join` as a live
  diagnostic.

### Platforms

- Release archives for macOS (Apple silicon and Intel), Linux (x64 and arm64,
  glibc 2.35 or newer) and Windows (x64), with shell and PowerShell
  installers, SHA-256 checksums and third-party licence notices.
- On Windows the data directory is `%LOCALAPPDATA%\rmule`, and the binaries
  link the C runtime statically.

[Unreleased]: https://github.com/Lazark0x/rmule/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/Lazark0x/rmule/releases/tag/v0.3.0
[0.2.0]: https://github.com/Lazark0x/rmule/releases/tag/v0.2.0
[0.1.0]: https://github.com/Lazark0x/rmule/releases/tag/v0.1.0
