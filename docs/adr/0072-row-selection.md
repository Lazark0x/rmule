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
  leaves it stays at the same height. The viewport moves no further than keeps it
  visible.
- Settings is a form, not a table: `j` / `k` step the focus and wrap, as `Tab` does.

## Consequences

- Every table answers the same keys the same way.
- A late batch of rows never slides another row under an action already on its way.
