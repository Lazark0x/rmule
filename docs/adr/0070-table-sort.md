# Every table is ordered by one view-owned Table Sort

## Context

The core publishes sets, not orders (ADR-0069). Every table in the TUI needs an order the
operator can change and a glyph golden can pin, and rows keep arriving while the operator
reads: a Kad walk adds search results long after a server answered. Labels will be
translated, so an order taken from rendered words would change with the language. aMule
compares a download's percentage alone (`DownloadListCtrl.cpp:1117-1118`) and ranks its
status (`PartFile.cpp:4638-4661`).

## Decision

Every table — Search results, Transfers and its Sources pane, Servers, Shared Files and
its Upload peers pane — is ordered by one **Table Sort**, owned by the view. The core
publishes sets, not orders.

- **Only a visible column sorts**; download id, list position and arrival order are not
  sort keys.
- **Gestures.** `s` moves the sort to the next column and wraps; `S` reverses it; a click
  on a header sorts by it, and on the header already holding the sort reverses it.
- **Natural Direction.** A column receiving the sort starts ascending if it is text and
  descending if it is a quantity.
- **A pane under a table sorts on its own**, with one durable sort shared by every
  download's sources. Its name column is the peer's endpoint, comparing digit runs as
  numbers. **Software** sorts by the client's family rank, then version, then mod
  (`ClientSoftware`'s own order). A source's **Phase** ranks how far it has got
  (receiving, verifying, requesting, hash set, queued, handshaking, connecting, idle,
  releasing, retired, shut down); an upload peer's **State** ranks slot-holders first,
  then the queue in its own order.
- **The default is name ascending in every table**, and the sort is per table and
  durable, a preference in the store. It is not per search.
- **Tie Chain.** Rows equal on the sort column order by name ascending, then by identity
  (file hash, download id, server endpoint), so the order is total and a glyph golden is
  deterministic. Reversing the sort does not reverse the chain.
- **Values.** Quantities compare as numbers, never as rendered text. Names compare
  case- and accent-folded, digit runs as numbers. A missing value sorts last in both
  directions.
- **Nothing sorts by a rendered word.** A cell showing an enumeration's label (a server's
  priority, a download's status) sorts by rank. Labels will be translated; only text the
  network or the operator supplied sorts as text.
- **A column's order may be a rank before a number.** A table may group rows ahead of
  the column's value, and the groups keep their order in both directions. Transfers'
  **Progress** and **Done** rank downloads moving bytes first, the completed next, then
  runs that are alive but move nothing (`Waiting`, `No network`), then those with no run
  (paused, failed), each group by its share. aMule compares the percentage alone
  (`DownloadListCtrl.cpp:1117-1118`), which scatters completed files at 100 %.
  **Status** keeps aMule's rank (`PartFile.cpp:4638-4661`: moving bytes, waiting,
  paused, complete, failed) and opens with the downloads moving bytes at the top.
- **A waiting row names what it waits on.** The core hands a starved run's wait as a
  code, `SourceWait`, again whenever it changes: a server session up (`Asking`) reads
  *Waiting*; no session with Kad running (`KadAlone`) reads *Asking Kad*; no session and
  Kad off (`NoSession`) reads *No network*, because the global sweep asks only with a
  session (ADR-0051). The Sources pane, the details' waiting row and the status bar say
  the same sentence; all three stay in aMule's waiting rank.
- **Rows re-order live and the cursor follows its row.** Freezing the order during a
  search would make the header arrow lie for the length of a Kad walk; an index cursor
  would let a late batch slide another file under an Enter already on its way.

## Consequences

- Every table order is total, so a glyph golden is deterministic.
- A translated label never changes an order.

## Considered options

- **A previous-sort-column tie-break.** Rejected: the order would depend on a history the
  screen does not show.
