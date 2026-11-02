# One line per row: a table cuts free text in the middle, and the selected row says it whole

## Context

The TUI's tables wrapped. A row that could not fit grew down, so every character of a name
stayed on screen and no renderer drew an ellipsis. The rule was written for the name in front
of the operator. It cost the list behind it.

At the default 80x24 the File column of Transfers had 17 cells. Seven ordinary file names showed
4 of 7 downloads, and all seven fit only from 110 columns wide. A real search of 426 results
showed 5 rows. Networks, the landing tab, showed one server of eleven, its name on four lines.
Wraps fell mid-word (`linu|x.pdf`), every row took a different height, so no column could be
scanned, and a row taller than its pane was dropped by the table widget while the cursor stayed
on it, so keys acted on a row nobody could see. Bounded columns held their width while the one
column that identifies the row was squeezed to nothing.

## Decision

**Every table draws one line per row, everywhere. Free text that does not fit is cut in the
middle, keeping its file extension. The selected row's full value rides the Off-screen line.**

- **The cut.** The start of a name and its end are what tell two files apart, and the extension
  says what the file is, so the cut falls between them, as `…`. The cut is measured in display
  cells and walked by grapheme cluster, so CJK and combining text never split a cell or an
  extension. A value in a cell too narrow for it reads as a shorter form first where it has one:
  a run-and-all-time pair drops the all-time figure.
- **The Off-screen line** says, for the selected row, the value of every column that gave way
  and the whole of every value a cell shortened. A value is never lost, only one key move away.
- **Columns give way before the name goes small.** Each column has a floor it is shown at or not
  at all, measured from its header and the words and units it draws, so a floor holds in any
  language. The greedy column's floor is the room it keeps: 30 cells for a file name, 20 for a
  server's. A pane that cannot hold every floor takes columns away in the table's stated order
  and says on its bottom border which. A column that gave way costs no gap.
- **One table.** Every table draws through `crate::table`, which owns the widths, the fitting, the
  selection mark, the Viewport and the Off-screen line, and asks a row for its cells only when it
  is on screen or selected. Alignment comes from the column's kind, so an amount sits right in
  every table.
- **A row is never dropped.** A row cannot be taller than its pane. A pane with one line for the
  table shows the cursor's row and lets the header give way, so keys act on what is seen.

- **The list keeps the screen.** Two panes stack by share and stand side by side from 160 cells;
  a pane with nothing to list takes the lines it says that in; `z` gives the focused pane the
  whole tab, and `Tab` carries the zoom across. The Kad panel gives way under 78 cells of tab and
  the log's border says so. Below 60×20 no view fits, and the terminal says so in place of panes
  that vanish: its size, the size it takes, and `q`, the one key that answers.

Prose still folds: a modal, the help, a log line and the Off-screen line itself are sentences,
not rows.

## Consequences

- At 80x24 Transfers shows its seven downloads, a search shows a page of its results, and Networks
  shows its servers. A row's height no longer has to be measured, so no table keeps a height memo
  and a click maps to a row by subtraction.
- A cut name reads differently from the one on disk. Two files that differ only in their middle
  look alike until the cursor is on one; the Off-screen line tells them apart.
- Moving the cursor between a row that fits and one that was cut moves the Off-screen line in and
  out, which moves the table's bottom edge by a line.
- The Off-screen line wraps and takes at most half the table, so a name of hundreds of characters
  can outrun it at the smallest panes; the pane's zoom gives it the room.
- The server table's grants and UDP flags no longer fit under it, and move behind a key
  (ADR-0080).

## Considered options

- **Keep wrapping and shrink the bounded columns harder.** Rejected: at 80 columns a name of 60
  cells takes three lines at best, and the list still loses a row in three.
- **Offer wrapping as a toggle.** Rejected: a second layout for every table, and the second one
  is the layout this decision removes. The Off-screen line reads any value whole.
- **Cut at the end.** Rejected: `Very.Long.Show.Name.S01E0…` hides what tells episodes apart, and
  the extension goes first.
- **A fixed File column with horizontal scrolling.** Rejected: it trades a cut for a hidden
  position and a mode the keys must learn.
