# Held Searches: every search of the run stays open as an entry

## Context

A search's results arrive over time, from a server and from a Kad walk, and an operator
often runs several searches in one sitting and returns to an earlier one. The query text
says what the operator looks for, and the Run Log never carries it (ADR-0075).

## Decision

- The Search tab keeps every search of the run as a **Held Search**, a strip of entries
  under the query input. An entry not in view keeps receiving results and shows its
  count and whether it is still running.
- A new query always opens a new entry and moves to it; the same text twice is two
  entries. There is no cap; the strip scrolls sideways.
- `x` stops a running search and keeps what arrived; on a finished search it closes the
  entry. `n` asks the entry's server for its next page (ADR-0036) while the core names
  the entry as its server's pager.
- **Nothing survives the run.** No query text is written to disk; the Run Log never
  carries query text.
- Each entry keeps its own cursor; the Table Sort (ADR-0070) is shared. A Related-Files Search opens
  as an entry like any other.
- An entry with no core to send through says so at once: on a UI-only run or after the
  core stopped, a new query opens an entry reading "not sent" and why, and the typed
  query stays in the input; a search running when the core stopped reads "stopped with
  the core".
- `[` / `]` move between a tab's sub-entries and mean nothing else: the Held Searches in
  Search, the shared-directory strip in Shared Files. Tabs are reached by the digits and
  `h` / `l`, panes by Tab / Shift-Tab.

## Consequences

- Returning to an earlier search costs nothing, and its results kept arriving meanwhile.
- A query leaves no trace on disk once the run ends.

## Considered options

- **A recall list of past query texts instead of Held Searches.** Rejected: it keeps only
  words, and a return to earlier results costs a new search.
- **Replacing the current search entry unless pinned.** Rejected: results are lost unless
  the operator thought ahead.
