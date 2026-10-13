# One Row Selection: the cursor is an identity that follows its row

## Context

Every table the Table Sort orders (ADR-0070) needs one way to move, select and act on a
row, and its rows re-order live while the operator reads.

## Decision

One **Row Selection** in every table the Table Sort names; the keys and the mark live in
`row_selection` and `table_sort/cursor.rs`.

- `j` / `↓` and `k` / `↑` move one row and stop at the ends; `g` / `G` go to the first and
  last row; the wheel is `↑` / `↓` on the focused pane. Home, End and the page keys are
  unbound. An empty table takes the keys and does nothing.
- A click selects and focuses; it never acts. `Enter` and `m` open the row menu, pinned to
  the selected row until it closes.
- The selected row wears `▸` in the gutter and the selection background, bold in the
  focused pane and dimmed but still marked in the others.
- The cursor is an identity: it follows its row through every re-order, and when its row
  leaves it stays at the same height. The **Viewport** moves no further than keeps it
  visible.
- Settings is a form, not a table: `j` / `k` step the focus and wrap, as `Tab` does.

### Viewport

Every scrollable list owns one **Viewport** beside its Row Selection
(`row_selection/viewport.rs`): its first item on screen, how many items the last draw
showed whole, and of how many. The draw writes it, and the list's scroll bar and count
are drawn from it; no view keeps a scroll offset or a count of its own.

- An item is what the list scrolls by: a row in a table, a menu or a strip, however many
  lines it wraps to; a line in the log, the help, the file details modal and the
  Settings form.
- A list with a cursor follows it: the first item moves no further than keeps the cursor
  wholly on screen. A list without one scrolls by the same keys — `j` / `k` a line, `g` /
  `G` the ends, the help's page keys a page — and stays where it was put while items
  arrive; one resting on its end keeps the end in view, and the log opens there.
- While the items outgrow the viewport, a scroll bar takes the list's inner right column:
  `▲` and `▼` at its ends once it is three cells tall, and a `█` thumb on a `║` track
  whose size and place are the visible window over the whole list. The thumb touches an
  end only when the list is at that end. A list that fits draws no bar.
- The thumb moves in eighths of a cell. Its length is the share of the list on screen, in
  eighths of the track, but at least a whole cell; its top is as far down the travel that
  length leaves as the list is scrolled through the places its first item can take, so the
  last page puts the thumb's end on the track's end exactly, where the share above the
  window would round it an eighth short. A cell the thumb fills is `█`; the cell its top
  edge falls in is the lower block of the thumb's share of it (`▁` to `▇`) in the thumb's
  style; the cell its bottom edge falls in is the complementary lower block in the thumb's
  style reversed, so the cell's top shows the thumb. Only the lower blocks are drawn: the
  upper-eighth ones are not reliably in fonts. Both edges in one cell take the edge glyph
  that overstates the thumb less. The track and the `▲` `▼` stay whole cells.
- A theme whose thumb colour is its track colour — its text colour the same as its dim
  one, as in a monochrome theme — draws the thumb in whole cells: a part-cell edge shows
  where the thumb ends by its colour alone.
- The column is the bar's only while the list overflows: a list that fits keeps every
  column for its items, so a table at the widths it was laid out for loses no cell to a
  bar it does not draw. A list with more items than lines surely overflows; a shorter one
  is laid out at its full width first and, when its wrapped rows overflow there, one
  column narrower. An overlay sized to its content — a menu, the details modal, the
  help — grows by the column instead when the frame has it.
- The bottom border carries the count at its right end: the cursor's row over the rows in
  a list with one, whether or not it overflows — Settings counts its rows, not its lines
  — and the last item on screen over the total in a list without, only while it
  overflows. The count gives way last: a gave-way note or a hint on the same border goes
  first. Its words are the words module's.
- A modal too tall for the frame scrolls under a Viewport of its own, with the bar and
  the count of a list: a confirm or the details by `j` / `k` / `g` / `G`; a form, whose
  fields take those letters, by `PageUp` / `PageDown` / `Home` / `End`, and it follows
  its focused field again as soon as a field takes a key. The first field answers for
  the lines above it and the last for the lines under it, so a rejection and the key
  legend come into view with the focus. A line wider than the modal wraps.
- A strip with no border of its own carries the count at its own end: the held-search
  strip only while its `‹` `›` markers hide an entry, the Shared Files directory strip on
  its hint line.

## Consequences

- Every table answers the same keys the same way.
- A late batch of rows never slides another row under an action already on its way.
- Every list says where the operator is in it the same way, from the one Viewport, and a
  list that fits says nothing more than where its cursor is.
